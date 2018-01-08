FROM alpine:3.5

ADD bin/cloud-controller-manager /usr/local/bin/cloud-controller-manager

CMD ["/bin/sh", "-c", "/usr/local/bin/cloud-controller-manager", "--master=http://127.0.0.1:8080", "--kubeconfig=/etc/kubernetes/node-kubeconfig.yaml", "--cloud-config=/etc/kubernetes/ucloud.gcfg", "--cloud-provider=ucloud"]
