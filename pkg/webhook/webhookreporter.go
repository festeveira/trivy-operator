package webhook

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/go-logr/logr"
	"k8s.io/apimachinery/pkg/api/errors"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"github.com/aquasecurity/trivy-operator/pkg/apis/aquasecurity/v1alpha1"
	"github.com/aquasecurity/trivy-operator/pkg/operator/etc"
	"github.com/aquasecurity/trivy-operator/pkg/operator/predicate"
)

type WebhookReconciler struct {
	logr.Logger
	etc.Config
	client.Client
}

const (
	Update string = "update"
	Delete string = "delete"
)

type WebhookMsg struct {
	Verb           string        `json:"verb"`
	OperatorObject client.Object `json:"operatorObject"`
}

// +kubebuilder:rbac:groups=aquasecurity.github.io,resources=vulnerabilityreports,verbs=get;list;watch;delete

func (r *WebhookReconciler) SetupWithManager(mgr ctrl.Manager) error {
	installModePredicate, err := predicate.InstallModePredicate(r.Config)
	if err != nil {
		return err
	}

	reportTypes := []func() client.Object{
		func() client.Object { return &v1alpha1.ClusterComplianceReport{} },
		func() client.Object { return &v1alpha1.ClusterConfigAuditReport{} },
		func() client.Object { return &v1alpha1.ClusterInfraAssessmentReport{} },
		func() client.Object { return &v1alpha1.ClusterRbacAssessmentReport{} },
		func() client.Object { return &v1alpha1.ClusterSbomReport{} },
		func() client.Object { return &v1alpha1.ClusterVulnerabilityReport{} },
		func() client.Object { return &v1alpha1.ConfigAuditReport{} },
		func() client.Object { return &v1alpha1.ExposedSecretReport{} },
		func() client.Object { return &v1alpha1.InfraAssessmentReport{} },
		func() client.Object { return &v1alpha1.RbacAssessmentReport{} },
		func() client.Object { return &v1alpha1.SbomReport{} },
		func() client.Object { return &v1alpha1.VulnerabilityReport{} },
	}

	for _, newReport := range reportTypes {
		err = ctrl.NewControllerManagedBy(mgr).
			For(newReport(), builder.WithPredicates(
				installModePredicate)).
			Complete(r.reconcileReport(newReport))
		if err != nil {
			return err
		}

	}
	return nil
}

func (r *WebhookReconciler) reconcileReport(newReport func() client.Object) reconcile.Func {
	return func(ctx context.Context, request reconcile.Request) (reconcile.Result, error) {
		log := r.Logger.WithValues("report", request.NamespacedName)
		verb := Update
		reportObj := newReport()
		err := r.Client.Get(ctx, request.NamespacedName, reportObj)
		if err != nil {
			if errors.IsNotFound(err) {
				return ctrl.Result{}, nil
			}
			return ctrl.Result{}, fmt.Errorf("getting report from cache: %w", err)
		}

		if r.WebhookSendDeletedReports {
			if reportObj.GetDeletionTimestamp() != nil {
				verb = Delete
				r.removeFinalizerFromReport(ctx, reportObj)
			}
		}

		if ignoreHistoricalReport(reportObj) {
			log.V(1).Info("Ignoring historical report")
			return ctrl.Result{}, nil
		}

		webhookBroadcastCustomHeaders := r.Config.GetWebhookBroadcastCustomHeaders()

		if r.WebhookSendDeletedReports {
			msg := WebhookMsg{OperatorObject: reportObj, Verb: verb}

			return ctrl.Result{}, sendReport(msg, r.WebhookBroadcastURL, *r.WebhookBroadcastTimeout, webhookBroadcastCustomHeaders)
		}
		return ctrl.Result{}, sendReport(reportObj, r.WebhookBroadcastURL, *r.WebhookBroadcastTimeout, webhookBroadcastCustomHeaders)
	}
}

func (r *WebhookReconciler) removeFinalizerFromReport(ctx context.Context, reportObj client.Object) error {
	finalizers := []string{}
	for _, f := range reportObj.GetFinalizers() {
		if f != finalizerName {
			finalizers = append(finalizers, f)
		}
	}
	reportObj.SetFinalizers(finalizers)
	if err := r.Client.Update(ctx, reportObj); err != nil {
		return fmt.Errorf("removing finalizer: %w", err)
	}
	return nil
}

func sendReport[T any](reports T, endpoint string, timeout time.Duration, headerValues http.Header) error {
	b, err := json.Marshal(reports)
	if err != nil {
		return fmt.Errorf("failed to marshal reports: %w", err)
	}
	hc := http.Client{
		Timeout: timeout,
	}

	req, err := http.NewRequest(http.MethodPost, endpoint, bytes.NewBuffer(b))
	if err != nil {
		return fmt.Errorf("failed to make a new request: %w", err)
	}

	headerValues.Set("Content-Type", "application/json")
	req.Header = headerValues

	resp, err := hc.Do(req)
	defer func() {
		if resp != nil {
			_ = resp.Body.Close()
		}
	}()
	if err != nil {
		return fmt.Errorf("failed to send reports to endpoint: %w", err)
	}
	return nil
}

func ignoreHistoricalReport(reportType client.Object) bool {
	ttlReportAnnotationStr, ok := reportType.GetAnnotations()[v1alpha1.TTLReportAnnotation]
	if !ok {
		return false
	}
	if ttlReportAnnotationStr == time.Duration(0).String() { // check if it marked as historical report
		return true
	}
	return false
}
