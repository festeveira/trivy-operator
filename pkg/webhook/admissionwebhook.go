package webhook

import (
	"context"

	"gomodules.xyz/jsonpatch/v2"

	admissionv1 "k8s.io/api/admission/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

const finalizerName = "aquasecurity.github.io/webhook-reporter-finalizer"

type AddFinalizerAdmissionWebhook struct {
	decoder admission.Decoder
}

func (w *AddFinalizerAdmissionWebhook) SetupWebhookWithManager(mgr ctrl.Manager) error {
	w.decoder = admission.NewDecoder(mgr.GetScheme())
	mgr.GetWebhookServer().Register(
		"/add-finalizer",
		&admission.Webhook{Handler: w},
	)
	return nil
}

func (w *AddFinalizerAdmissionWebhook) Handle(ctx context.Context, req admission.Request) admission.Response {
	if req.Operation != admissionv1.Create {
		return admission.Allowed("non-create request")
	}

	obj := &unstructured.Unstructured{}
	if err := w.decoder.Decode(req, obj); err != nil {
		return admission.Errored(400, err)
	}

	found := false
	patchOp := "add"
	if len(obj.GetFinalizers()) != 0 {
		for _, f := range obj.GetFinalizers() {
			if f == finalizerName {
				found = true
				break
			}
		}
		patchOp = "replace"
	}

	if !found {
		patch := jsonpatch.NewOperation(
			patchOp,
			"/metadata/finalizers",
			append(obj.GetFinalizers(), finalizerName),
		)
		return admission.Patched("added finalizer", patch)
	}

	return admission.Allowed("nothing to do")
}

func (w *AddFinalizerAdmissionWebhook) InjectDecoder(d admission.Decoder) error {
	w.decoder = d
	return nil
}
