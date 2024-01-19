#!/usr/bin/env bash


echo "[Manual]" 'Run the below command (based on the file location on your system) on the each worker node. For example:
chmod u-x,go-wx /etc/systemd/system/kubelet.service.d/10-kubeadm.conf

Default: the kubelet service file has permissions of 640.'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'Run the below command (based on the file location on your system) on the each worker node. For example:
chown root:root /etc/systemd/system/kubelet.service.d/10-kubeadm.conf

Default: kubelet service file ownership is set to root:root.'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'Run the below command (based on the kube-proxy --kubeconfig file location on your system if exists) on the node. For example:
chmod u-x,go-rwx <proxy kubeconfig file>'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'Run the below command (based on the kube-proxy --kubeconfig file location on your system if exists) on the each worker node. For example:
chown root:root <proxy kubeconfig file>'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'Run the below command (based on the --kubeconfig file location on your system) on the each worker node. For example:
chmod u-x,go-rwx /etc/kubernetes/kubelet.conf

Default: kubelet.conf file has permissions of 640.'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'Run the below command (based on the --kubeconfig file location on your system) on the each worker node. For example:
chown root:root /etc/kubernetes/kubelet.conf

Default: kubelet.conf file ownership is set to root:root.'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'Run the following command to modify the file permissions of the --client-ca-file:
chmod u-x,go-wx <filename>

Default: no --client-ca-file is specified.'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'Run the following command to modify the ownership of the --client-ca-file. 
chown root:root <filename>

Default: no --client-ca-file is specified.'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'Run the following command (based on the --config file location on your system): 
chmod u-x,go-wx /var/lib/kubelet/config.yaml

Default: the /var/lib/kubelet/config.yaml file as set up by kubeadm has permissions of 600.'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'Run the following command (based on the kubelet --config file location on your system). For example:
chown root:root /etc/kubernetes/kubelet.conf

Default: /var/lib/kubelet/config.yaml file as set up by kubeadm is owned by root:root.'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'If using a Kubelet config file (--config file), edit the file to set 
authentication: anonymous: enabled
to false. 
If using executable arguments, edit the kubelet service file (ex. /etc/systemd/system/kubelet.service.d/10-kubeadm.conf) and set the below parameter in KUBELET_SYSTEM_PODS_ARGS variable:
--anonymous-auth=false 
Based on your system, restart the kubelet service. For example: 
systemctl daemon-reload systemctl 
restart kubelet.service

Default: anonymous access is enabled.'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'If using a Kubelet config file, edit the file to set authorization: mode to Webhook. 
If using executable arguments, edit the kubelet service file (ex. /etc/systemd/system/kubelet.service.d/10-kubeadm.conf) and set the below parameter in KUBELET_AUTHZ_ARGS variable:
--authorization-mode=Webhook 
Based on your system, restart the kubelet service. For example: 
systemctl daemon-reload systemctl 
restart kubelet.service

Default: --authorization-mode argument is set to AlwaysAllow.'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'If using a Kubelet config file, edit the file to set '\''authentication: x509: clientCAFile'\'' to the location of the client CA file. 
If using command line arguments, edit the kubelet service file (ex. /etc/systemd/system/kubelet.service.d/10-kubeadm.conf) and set the below parameter in KUBELET_AUTHZ_ARGS variable: 
--client-ca-file=<path/to/client-ca-file> 
Based on your system, restart the kubelet service. For example: 
systemctl daemon-reload systemctl 
restart kubelet.service

Default: --client-ca-file argument is not set.'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'If using a Kubelet config file, edit the file to set readOnlyPort to 0. 
If using command line arguments, edit the kubelet service file (ex. /etc/systemd/system/kubelet.service.d/10-kubeadm.conf) and set the below parameter in KUBELET_SYSTEM_PODS_ARGS variable. 
--read-only-port=0 
Based on your system, restart the kubelet service. For example: 
systemctl daemon-reload systemctl 
restart kubelet.service

Default: 10255.'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'If using a Kubelet config file, edit the file to set streamingConnectionIdleTimeout to a value other than 0. 
If using command line arguments, edit the kubelet service file (ex. /etc/systemd/system/kubelet.service.d/10-kubeadm.conf) and set the below parameter in KUBELET_SYSTEM_PODS_ARGS variable to needed value but not 0: 
--streaming-connection-idle-timeout=5m 
Based on your system, restart the kubelet service. For example: 
systemctl daemon-reload systemctl 
restart kubelet.service

Default: --streaming-connection-idle-timeout is set to 4 hours.'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'If using a Kubelet config file, edit the file to set protectKernelDefaults: true. 
If using command line arguments, edit the kubelet service file (ex. /etc/systemd/system/kubelet.service.d/10-kubeadm.conf) and set the below parameter in KUBELET_SYSTEM_PODS_ARGS variable. 
--protect-kernel-defaults=true 
Based on your system, restart the kubelet service. For example: 
systemctl daemon-reload systemctl 
restart kubelet.service

Default: --protect-kernel-defaults is not set.'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'If using a Kubelet config file, edit the file to set makeIPTablesUtilChains: true. 
If using command line arguments, edit the kubelet service file (ex. /etc/systemd/system/kubelet.service.d/10-kubeadm.conf) and remove the --make-iptables-util-chains argument from the KUBELET_SYSTEM_PODS_ARGS variable or set it to true. 
Based on your system, restart the kubelet service. For example: 
systemctl daemon-reload 
systemctl restart kubelet.service

Default: true.'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'Edit the kubelet service file (ex. /etc/systemd/system/kubelet.service.d/10-kubeadm.conf) and remove the --hostname-override argument from the KUBELET_SYSTEM_PODS_ARGS variable. 
Based on your system, restart the kubelet service. For example: 
systemctl daemon-reload systemctl 
restart kubelet.service

Default: --hostname-override argument is not set.'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'If using a Kubelet config file, edit the file to set eventRecordQPS: to an appropriate high level (recommended is 1000 or higher).
If using command line arguments, edit the kubelet service file (ex. /etc/systemd/system/kubelet.service.d/10-kubeadm.conf) and set the below parameter in KUBELET_SYSTEM_PODS_ARGS variable to an appropriate high level (recommended is 1000 or higher), example:
--event-qps=1000
Based on your system, restart the kubelet service. For example: 
systemctl daemon-reload 
systemctl restart kubelet.service

Default: 5.'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'If using a Kubelet config file, edit the file to set tlsCertFile to the location of the certificate file to use to identify this Kubelet, and tlsPrivateKeyFile to the location of the corresponding private key file. 
If using command line arguments, edit the kubelet service file (ex. /etc/systemd/system/kubelet.service.d/10-kubeadm.conf) and set the below parameters in KUBELET_CERTIFICATE_ARGS variable. 
--tls-cert-file=<path/to/tls-certificate-file> --tls-private-key-file=<path/to/tls-key-file>
Based on your system, restart the kubelet service. For example: 
systemctl daemon-reload systemctl 
restart kubelet.service

Default: if --tls-cert-file and --tls-private-key-file are not provided, a self-signed certificate and key are generated for the public address and saved to the directory passed to --cert-dir.'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'If using a Kubelet config file, edit the file to add the line rotateCertificates: true or remove it altogether to use the default value. 
If using command line arguments, edit the kubelet service file (ex. /etc/systemd/system/kubelet.service.d/10-kubeadm.conf) and remove --rotate-certificates=false argument from the KUBELET_CERTIFICATE_ARGS variable or set it to true. 
Based on your system, restart the kubelet service. For example: 
systemctl daemon-reload systemctl 
restart kubelet.service

Default: kubelet client certificate rotation is enabled.'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'Edit the kubelet service file (ex. /etc/systemd/system/kubelet.service.d/10-kubeadm.conf) and set the below parameter in KUBELET_CERTIFICATE_ARGS variable:
--feature-gates=RotateKubeletServerCertificate=true 
Based on your system, restart the kubelet service. For example: 
systemctl daemon-reload systemctl 
restart kubelet.service

Default: RotateKubeletServerCertificate is true.'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'If using a Kubelet config file, edit the file to set TLSCipherSuites: to TLS_AES_128_GCM_SHA256,TLS_AES_256_GCM_SHA384,TLS_CHACHA20_POLY1305_SHA256,TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,TLS_RSA_WITH_AES_128_CBC_SHA,TLS_RSA_WITH_AES_128_GCM_SHA256,TLS_RSA_WITH_AES_256_CBC_SHA,TLS_RSA_WITH_AES_256_GCM_SHA384 or to a subset of these values. 
If using executable arguments, edit the kubelet service file (ex. /etc/systemd/system/kubelet.service.d/10-kubeadm.conf) and set the --tls-cipher-suites parameter as follows, or to a subset of these values:
--tls-cipher-suites=TLS_AES_128_GCM_SHA256,TLS_AES_256_GCM_SHA384,TLS_CHACHA20_POLY1305_SHA256,TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,TLS_RSA_WITH_AES_128_CBC_SHA,TLS_RSA_WITH_AES_128_GCM_SHA256,TLS_RSA_WITH_AES_256_CBC_SHA,TLS_RSA_WITH_AES_256_GCM_SHA384
Based on your system, restart the kubelet service. For example: 
systemctl daemon-reload systemctl 
restart kubelet.service

Default: the default Go cipher suites will be used.'
read -n 1 -p "Press Enter to continue..."



