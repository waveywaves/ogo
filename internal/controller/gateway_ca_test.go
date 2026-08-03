/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package controller

import (
	"context"
	"strings"
	"testing"

	ogov1alpha1 "github.com/aknochow/ogo/api/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	clientfake "sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestReconcileGatewayCAConfigMap(t *testing.T) {
	ctx := context.Background()
	gw := testGateway()
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: gatewayServerTLSSecretName(gw), Namespace: gatewayNamespace(gw)},
		Data: map[string][]byte{
			gatewayCAKey:            []byte("ca-one"),
			corev1.TLSCertKey:       []byte("server-certificate"),
			corev1.TLSPrivateKeyKey: []byte("private-key"),
		},
	}
	r := &OpenShellGatewayReconciler{Client: newGatewayCAClient(secret)}

	if err := r.reconcileGatewayCAConfigMap(ctx, gw); err != nil {
		t.Fatal(err)
	}
	cm := getGatewayCAConfigMap(t, r.Client, gw)
	assertCAOnly(t, cm, "ca-one")
	resourceVersion := cm.ResourceVersion
	if err := r.reconcileGatewayCAConfigMap(ctx, gw); err != nil {
		t.Fatal(err)
	}
	cm = getGatewayCAConfigMap(t, r.Client, gw)
	if cm.ResourceVersion != resourceVersion {
		t.Fatalf("unchanged ConfigMap resourceVersion = %q, want %q", cm.ResourceVersion, resourceVersion)
	}

	storedSecret := &corev1.Secret{}
	if err := r.Get(ctx, client.ObjectKeyFromObject(secret), storedSecret); err != nil {
		t.Fatal(err)
	}
	storedSecret.Data[gatewayCAKey] = []byte("ca-two")
	if err := r.Update(ctx, storedSecret); err != nil {
		t.Fatal(err)
	}
	cm.Data["legacy.crt"] = "stale"
	cm.BinaryData = map[string][]byte{"ca.crt": []byte("stale")}
	if err := r.Update(ctx, cm); err != nil {
		t.Fatal(err)
	}

	if err := r.reconcileGatewayCAConfigMap(ctx, gw); err != nil {
		t.Fatal(err)
	}
	assertCAOnly(t, getGatewayCAConfigMap(t, r.Client, gw), "ca-two")
}

func TestReconcileGatewayCAConfigMapFallsBackToTLSCertificate(t *testing.T) {
	gw := testGateway()
	gw.Spec.TLS.ServerCertSecretName = "custom-tls"
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "custom-tls", Namespace: gatewayNamespace(gw)},
		Data:       map[string][]byte{corev1.TLSCertKey: []byte("certificate-chain"), corev1.TLSPrivateKeyKey: []byte("private-key")},
	}
	r := &OpenShellGatewayReconciler{Client: newGatewayCAClient(secret)}

	if err := r.reconcileGatewayCAConfigMap(context.Background(), gw); err != nil {
		t.Fatal(err)
	}
	assertCAOnly(t, getGatewayCAConfigMap(t, r.Client, gw), "certificate-chain")
}

func TestReconcileGatewayCAConfigMapRejectsUnmanagedCollision(t *testing.T) {
	gw := testGateway()
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: gatewayServerTLSSecretName(gw), Namespace: gatewayNamespace(gw)},
		Data:       map[string][]byte{gatewayCAKey: []byte("new-ca")},
	}
	unmanaged := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Name: gatewayCAConfigMapName(gw), Namespace: gatewayNamespace(gw)},
		Data:       map[string]string{gatewayCAKey: "user-ca"},
	}
	r := &OpenShellGatewayReconciler{Client: newGatewayCAClient(secret, unmanaged)}

	err := r.reconcileGatewayCAConfigMap(context.Background(), gw)
	if err == nil || !strings.Contains(err.Error(), "not managed by OGO") {
		t.Fatalf("error = %v, want unmanaged ConfigMap conflict", err)
	}
	cm := getGatewayCAConfigMap(t, r.Client, gw)
	if cm.Data[gatewayCAKey] != "user-ca" || len(cm.Labels) != 0 {
		t.Fatalf("unmanaged ConfigMap was changed: %#v", cm)
	}
}

func TestReconcileGatewayCAConfigMapKeepsLastValidData(t *testing.T) {
	gw := testGateway()
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: gatewayServerTLSSecretName(gw), Namespace: gatewayNamespace(gw)},
		Data:       map[string][]byte{corev1.TLSPrivateKeyKey: []byte("private-key")},
	}
	cm := managedGatewayCAConfigMap(gw, gatewayNamespace(gw), "last-valid-ca")
	r := &OpenShellGatewayReconciler{Client: newGatewayCAClient(secret, cm)}

	if err := r.reconcileGatewayCAConfigMap(context.Background(), gw); err == nil {
		t.Fatal("expected missing CA data error")
	}
	assertCAOnly(t, getGatewayCAConfigMap(t, r.Client, gw), "last-valid-ca")
}

func TestDeleteManagedGatewayCAConfigMaps(t *testing.T) {
	ctx := context.Background()
	gw := testGateway()
	current := managedGatewayCAConfigMap(gw, gatewayNamespace(gw), "current")
	stale := managedGatewayCAConfigMap(gw, "old-namespace", "stale")
	unrelated := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Name: "other", Namespace: "old-namespace", Labels: gatewayLabels(gw)},
	}
	unmanaged := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Name: gatewayCAConfigMapName(gw), Namespace: "user-namespace"},
		Data:       map[string]string{gatewayCAKey: "user-ca"},
	}
	r := &OpenShellGatewayReconciler{Client: newGatewayCAClient(current, stale, unrelated, unmanaged)}

	if err := r.deleteManagedGatewayCAConfigMaps(ctx, gw, gatewayNamespace(gw)); err != nil {
		t.Fatal(err)
	}
	assertConfigMapExists(t, r.Client, current)
	assertConfigMapMissing(t, r.Client, stale)
	assertConfigMapExists(t, r.Client, unrelated)
	assertConfigMapExists(t, r.Client, unmanaged)

	if err := r.deleteManagedGatewayCAConfigMaps(ctx, gw, ""); err != nil {
		t.Fatal(err)
	}
	assertConfigMapMissing(t, r.Client, current)
	assertConfigMapExists(t, r.Client, unrelated)
	assertConfigMapExists(t, r.Client, unmanaged)
}

func TestReconcileTLSPublishesGeneratedGatewayCA(t *testing.T) {
	gw := testGateway()
	r := &OpenShellGatewayReconciler{Client: newGatewayCAClient()}

	if err := r.reconcileTLS(context.Background(), gw); err != nil {
		t.Fatal(err)
	}
	secret := &corev1.Secret{}
	if err := r.Get(context.Background(), types.NamespacedName{Name: gatewayServerTLSSecretName(gw), Namespace: gatewayNamespace(gw)}, secret); err != nil {
		t.Fatal(err)
	}
	cm := getGatewayCAConfigMap(t, r.Client, gw)
	assertCAOnly(t, cm, string(secret.Data[gatewayCAKey]))
}

func TestReconcileTLSDisabledRemovesManagedGatewayCA(t *testing.T) {
	gw := testGateway()
	gw.Spec.TLS.Enabled = ptr.To(false)
	cm := managedGatewayCAConfigMap(gw, gatewayNamespace(gw), "ca")
	r := &OpenShellGatewayReconciler{Client: newGatewayCAClient(cm)}

	if err := r.reconcileTLS(context.Background(), gw); err != nil {
		t.Fatal(err)
	}
	assertConfigMapMissing(t, r.Client, cm)
}

func testGateway() *ogov1alpha1.OpenShellGateway {
	return &ogov1alpha1.OpenShellGateway{
		ObjectMeta: metav1.ObjectMeta{Name: "test-gateway"},
		Spec:       ogov1alpha1.OpenShellGatewaySpec{Namespace: "test-namespace"},
	}
}

func managedGatewayCAConfigMap(gw *ogov1alpha1.OpenShellGateway, namespace, ca string) *corev1.ConfigMap {
	return &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Name: gatewayCAConfigMapName(gw), Namespace: namespace, Labels: gatewayLabels(gw)},
		Data:       map[string]string{gatewayCAKey: ca},
	}
}

func getGatewayCAConfigMap(t *testing.T, c client.Client, gw *ogov1alpha1.OpenShellGateway) *corev1.ConfigMap {
	t.Helper()
	cm := &corev1.ConfigMap{}
	if err := c.Get(context.Background(), types.NamespacedName{Name: gatewayCAConfigMapName(gw), Namespace: gatewayNamespace(gw)}, cm); err != nil {
		t.Fatal(err)
	}
	return cm
}

func assertCAOnly(t *testing.T, cm *corev1.ConfigMap, want string) {
	t.Helper()
	if len(cm.Data) != 1 || cm.Data[gatewayCAKey] != want || len(cm.BinaryData) != 0 {
		t.Fatalf("ConfigMap data = %#v, binaryData = %#v, want only %s", cm.Data, cm.BinaryData, gatewayCAKey)
	}
	if cm.Labels[labelManagedBy] != managedByValue || cm.Labels[labelInstance] != "test-gateway" {
		t.Fatalf("ConfigMap labels = %#v, want OGO ownership", cm.Labels)
	}
}

func assertConfigMapExists(t *testing.T, c client.Client, cm *corev1.ConfigMap) {
	t.Helper()
	if err := c.Get(context.Background(), client.ObjectKeyFromObject(cm), &corev1.ConfigMap{}); err != nil {
		t.Fatalf("ConfigMap %s/%s should exist: %v", cm.Namespace, cm.Name, err)
	}
}

func assertConfigMapMissing(t *testing.T, c client.Client, cm *corev1.ConfigMap) {
	t.Helper()
	err := c.Get(context.Background(), client.ObjectKeyFromObject(cm), &corev1.ConfigMap{})
	if !apierrors.IsNotFound(err) {
		t.Fatalf("ConfigMap %s/%s should be deleted: %v", cm.Namespace, cm.Name, err)
	}
}

func newGatewayCAClient(objects ...client.Object) client.Client {
	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		panic(err)
	}
	return clientfake.NewClientBuilder().WithScheme(scheme).WithObjects(objects...).Build()
}
