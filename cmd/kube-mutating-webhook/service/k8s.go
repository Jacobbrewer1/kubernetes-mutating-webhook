package service

import metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

func isPodResource(res metav1.GroupVersionResource) bool {
	podResource := metav1.GroupVersionResource{Group: "", Version: "v1", Resource: "pods"}
	return res == podResource
}
