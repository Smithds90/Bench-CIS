#!/usr/bin/env bash

kubelet_conf_file=$(ps --no-headers o args p $(pidof kubelet) 2>/dev/null | grep -Ei "\s--config=" | sed -r 's#.*\s--config=("[^"]*"|[^"]\S*).*#\1#' | sed -e 's/^"//' -e 's/"$//')

static_pp=$(c_a=$(grep "staticPodPath:" "$kubelet_conf_file" | sed 's/staticPodPath:\s*//'); if [[ -n "$c_a" ]]; then echo "$c_a"; else ps --no-headers o args p $(pidof kubelet) 2>/dev/null | grep -Ei "\s--pod-manifest-path=" | sed -r 's#.*\s--pod-manifest-path=("[^"]*"|[^"]\S*).*#\1#' | sed -e 's/^"//' -e 's/"$//'; fi)

api_conf_file=$(grep -lEi "^\s*component:\s*kube-apiserver\s*$" "$static_pp"/*)

controlman_conf_file=$(grep -lEi "^\s*component:\s*kube-controller-manager\s*$" "$static_pp"/*)

scheduler_conf_file=$(grep -lEi "^\s*component:\s*kube-scheduler\s*$" "$static_pp"/*)

etcd_conf_file=$(grep -lEi "^\s*component:\s*etcd\s*$" "$static_pp"/*)


chmod u-x,go-wx "$api_conf_file"


chown root:root "$api_conf_file"


chmod u-x,go-wx "$controlman_conf_file"


chown root:root "$controlman_conf_file"


chmod u-x,go-wx "$scheduler_conf_file"


chown root:root "$scheduler_conf_file"


chmod u-x,go-wx "$etcd_conf_file"


chown root:root "$etcd_conf_file"


c_a=$(ps --no-headers o args p $(pidof kubelet) | grep -Ei "\s--cni-conf-dir="); if [ -n "$c_a" ]; then chmod u-x,go-wx $(echo "$c_a" | sed -r 's#.*\s--cni-conf-dir=("[^"]*"|[^"]\S*).*#\1/*#'); else chmod u-x,go-wx /etc/cni/net.d/*; fi


c_a=$(ps --no-headers o args p $(pidof kubelet) | grep -Ei "\s--cni-conf-dir="); if [ -n "$c_a" ]; then chown root:root $(echo "$c_a" | sed -r 's#.*\s--cni-conf-dir=("[^"]*"|[^"]\S*).*#\1/*#'); else chown root:root /etc/cni/net.d/*; fi


c_a=$(ps --no-headers o args p $(pidof etcd) | grep -Ei "\s--data-dir="); if [ -n "$c_a" ]; then chmod go-rwx $(echo "$c_a" | sed -r 's#.*\s--data-dir=("[^"]*"|[^"]\S*).*#\1#'); else chmod go-rwx /var/lib/etcd; fi


echo "[Manual]" 'On the etcd server node, get the etcd data directory, passed as an argument --data-dir, from the below command: 
ps -ef | grep etcd 
Change owner of the data directory to etcd:etcd (based on the etcd data directory found above). For example: 
chown etcd:etcd /var/lib/etcd'
read -n 1 -p "Press Enter to continue..."


chmod u-x,go-rwx /etc/kubernetes/admin.conf


chown root:root /etc/kubernetes/admin.conf


c_a=$(ps --no-headers o args p $(pidof kube-scheduler) | grep -Ei "\s--authentication-kubeconfig="); [ -n "$c_a" ] && chmod u-x,go-rwx $(echo "$c_a" | sed -r 's#.*\s--authentication-kubeconfig=("[^"]*"|[^"]\S*).*#\1#'); c_b=$(ps --no-headers o args p $(pidof kube-scheduler) | grep -Ei "\s--authorization-kubeconfig="); [ -n "$c_b" ] && chmod u-x,go-rwx $(echo "$c_b" | sed -r 's#.*\s--authorization-kubeconfig=("[^"]*"|[^"]\S*).*#\1#'); c_c=$(ps --no-headers o args p $(pidof kube-scheduler) | grep -Ei "\s--kubeconfig="); [ -n "$c_c" ] && chmod u-x,go-rwx $(echo "$c_c" | sed -r 's#.*\s--kubeconfig=("[^"]*"|[^"]\S*).*#\1#')


c_a=$(ps --no-headers o args p $(pidof kube-scheduler) | grep -Ei "\s--authentication-kubeconfig="); [ -n "$c_a" ] && chown root:root $(echo "$c_a" | sed -r 's#.*\s--authentication-kubeconfig=("[^"]*"|[^"]\S*).*#\1#'); c_b=$(ps --no-headers o args p $(pidof kube-scheduler) | grep -Ei "\s--authorization-kubeconfig="); [ -n "$c_b" ] && chown root:root $(echo "$c_b" | sed -r 's#.*\s--authorization-kubeconfig=("[^"]*"|[^"]\S*).*#\1#'); c_c=$(ps --no-headers o args p $(pidof kube-scheduler) | grep -Ei "\s--kubeconfig="); [ -n "$c_c" ] && chown root:root $(echo "$c_c" | sed -r 's#.*\s--kubeconfig=("[^"]*"|[^"]\S*).*#\1#')


c_a=$(ps --no-headers o args p $(pidof kube-controller-manager) | grep -Ei "\s--authentication-kubeconfig="); [ -n "$c_a" ] && chmod u-x,go-rwx $(echo "$c_a" | sed -r 's#.*\s--authentication-kubeconfig=("[^"]*"|[^"]\S*).*#\1#'); c_b=$(ps --no-headers o args p $(pidof kube-controller-manager) | grep -Ei "\s--authorization-kubeconfig="); [ -n "$c_b" ] && chmod u-x,go-rwx $(echo "$c_b" | sed -r 's#.*\s--authorization-kubeconfig=("[^"]*"|[^"]\S*).*#\1#'); c_c=$(ps --no-headers o args p $(pidof kube-controller-manager) | grep -Ei "\s--kubeconfig="); [ -n "$c_c" ] && chmod u-x,go-rwx $(echo "$c_c" | sed -r 's#.*\s--kubeconfig=("[^"]*"|[^"]\S*).*#\1#')


c_a=$(ps --no-headers o args p $(pidof kube-controller-manager) | grep -Ei "\s--authentication-kubeconfig="); [ -n "$c_a" ] && chown root:root $(echo "$c_a" | sed -r 's#.*\s--authentication-kubeconfig=("[^"]*"|[^"]\S*).*#\1#'); c_b=$(ps --no-headers o args p $(pidof kube-controller-manager) | grep -Ei "\s--authorization-kubeconfig="); [ -n "$c_b" ] && chown root:root $(echo "$c_b" | sed -r 's#.*\s--authorization-kubeconfig=("[^"]*"|[^"]\S*).*#\1#'); c_c=$(ps --no-headers o args p $(pidof kube-controller-manager) | grep -Ei "\s--kubeconfig="); [ -n "$c_c" ] && chown root:root $(echo "$c_c" | sed -r 's#.*\s--kubeconfig=("[^"]*"|[^"]\S*).*#\1#')


chown root:root $(find /etc/kubernetes/pki/ -type f)


chmod u-x,go-wx $(find /etc/kubernetes/pki/ -type f -name *.crt)


chmod u-x,go-rwx $(find /etc/kubernetes/pki/ -type f -name *.key)


echo "[Manual]" 'Edit the API server pod specification file /etc/kubernetes/manifests/kube-apiserver.yaml on the master node and set the below parameter. 
--anonymous-auth=false

Default: anonymous access is enabled.'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'In versions 1.18 and lower follow the documentation and configure alternate mechanisms for authentication. Then, edit the API server pod specification file /etc/kubernetes/manifests/kube-apiserver.yaml on the master node and remove the --basic-auth-file=<filename> parameter.
In versions 1.19 and higher support for basic authentication was removed.

Default: basic authentication is not set.'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'Follow the documentation and configure alternate mechanisms for authentication. Then, edit the API server pod specification file /etc/kubernetes/manifests/kube-apiserver.yaml on the master node and remove the --token-auth-file=<filename> parameter.

Default: --token-auth-file argument is not set.'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'In versions 1.18 and lower edit the API server pod specification file /etc/kubernetes/manifests/kube-apiserver.yaml on the master node and remove the --kubelet-https parameter.
Versions 1.19 and higher always use https for kubelet connections.

Default: kubelet connections are over https.'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'Follow the Kubernetes documentation and set up the TLS connection between the apiserver and kubelets. Then, edit API server pod specification file /etc/kubernetes/manifests/kube-apiserver.yaml on the master node and set the kubelet client certificate and key parameters as below. 
--kubelet-client-certificate=<path/to/client-certificate-file> --kubelet-client-key=<path/to/client-key-file>

Default: certificate-based kubelet authentication is not set.'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'Follow the Kubernetes documentation and setup the TLS connection between the apiserver and kubelets. Then, edit the API server pod specification file /etc/kubernetes/manifests/kube-apiserver.yaml on the master node and set the -kubelet-certificate-authority parameter to the path to the cert file for the certificate authority. 
--kubelet-certificate-authority=<ca-string>

Default: --kubelet-certificate-authority argument is not set.'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'Edit the API server pod specification file /etc/kubernetes/manifests/kube-apiserver.yaml on the master node and set the --authorization-mode parameter to values other than AlwaysAllow. One such example could be as below. 
--authorization-mode=RBAC

Default: AlwaysAllow.'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'Edit the API server pod specification file /etc/kubernetes/manifests/kube-apiserver.yaml on the master node and set the --authorization-mode parameter to a value that includes Node. 
--authorization-mode=Node,RBAC

Default: AlwaysAllow.'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'Edit the API server pod specification file /etc/kubernetes/manifests/kube-apiserver.yaml on the master node and set the --authorization-mode parameter to a value that includes RBAC, for example: 
--authorization-mode=Node,RBAC

Default: AlwaysAllow.'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'Follow the Kubernetes documentation and set the desired limits in a configuration file. Then, edit the API server pod specification file /etc/kubernetes/manifests/kube-apiserver.yaml and set the below parameters. 
--enable-admission-plugins=...,EventRateLimit,... 
--admission-control-config-file=<path/to/configuration/file>

Default: EventRateLimit is not enabled.'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'Edit the API server pod specification file /etc/kubernetes/manifests/kube-apiserver.yaml on the master node and set the --enable-admission-plugins parameter to include AlwaysPullImages. 
--enable-admission-plugins=...,AlwaysPullImages,...

Default: AlwaysPullImages is not enabled.'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'Edit the API server pod specification file /etc/kubernetes/manifests/kube-apiserver.yaml on the master node and set the --enable-admission-plugins parameter to include SecurityContextDeny, unless PodSecurityPolicy is already in place. 
--enable-admission-plugins=...,SecurityContextDeny,...

Default: SecurityContextDeny is not enabled.'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'Follow the documentation and create ServiceAccount objects as per your environment. Then, edit the API server pod specification file /etc/kubernetes/manifests/kube-apiserver.yaml on the master node and ensure that the --disable-admission-plugins parameter is set to a value that does not include ServiceAccount.

Default: ServiceAccount admission controller is enabled.'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'Edit the API server pod specification file /etc/kubernetes/manifests/kube-apiserver.yaml on the master node and set the --disable-admission-plugins parameter to ensure it does not include NamespaceLifecycle.

Default: NamespaceLifecycle admission controller is enabled.'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'Pod Security Admission is enabled by default on all clusters using Kubernetes 1.23 or higher. In lower versions PodSecurityPolicy admission controller should be used. The PodSecurityPolicy admission controller is available in versions v1.24 and lower. Configure PodSecurityPolicy or PodSecurity admission controller.
To configure PodSecurityPolicy admission controller:
Follow the documentation and create Pod Security Policy objects as per your environment. Then, edit the API server pod specification file /etc/kubernetes/manifests/kube-apiserver.yaml on the master node and set the --enable-admission-plugins parameter to a value that includes PodSecurityPolicy: 
--enable-admission-plugins=...,PodSecurityPolicy,... 
Then restart the API Server.
To configure PodSecurity admission controller:
Ensure that the PodSecurity admission controller is not disabled with --disable-admission-plugins parameter in API server configuration.
Follow documentation to configure labels for namespaces to set needed security levels and actions (see at https://kubernetes.io/docs/concepts/security/pod-security-admission/ and https://kubernetes.io/docs/tasks/configure-pod-container/enforce-standards-admission-controller/). 

Default: PodSecurityPolicy admission controller is not enabled. In versions v1.23 and later PodSecurity admission controller is enabled.'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'Follow the Kubernetes documentation and configure NodeRestriction plug-in on kubelets. Then, edit the API server pod specification file /etc/kubernetes/manifests/kube-apiserver.yaml on the master node and set the --enable-admission-plugins parameter to a value that includes NodeRestriction. 
--enable-admission-plugins=...,NodeRestriction,...

Default: NodeRestriction is not enabled.'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'Edit the API server pod specification file /etc/kubernetes/manifests/kube-apiserver.yaml on the master node and remove the --insecure-bind-address parameter.
In versions 1.24 and higher the --insecure-bind-address flag was removed.

Default: the insecure bind address is not set.'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'Edit the API server pod specification file /etc/kubernetes/manifests/kube-apiserver.yaml on the master node and set the below parameter. 
--insecure-port=0
In versions 1.21 and higher the --insecure-port flag has no effect. It was removed in version 1.24.

Default: the insecure port is set to 8080.'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'Edit the API server pod specification file /etc/kubernetes/manifests/kube-apiserver.yaml on the master node and either remove the --secure-port parameter or set it to a different (non-zero) desired port.

Default: port 6443 is used as the secure port.'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'Edit the API server pod specification file /etc/kubernetes/manifests/kube-apiserver.yaml on the master node and set the below parameter. 
--profiling=false

Default: profiling is enabled.'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'Edit the API server pod specification file /etc/kubernetes/manifests/kube-apiserver.yaml on the master node and set the --audit-log-path parameter to a suitable path and file where you would like audit logs to be written, for example: 
--audit-log-path=/var/log/apiserver/audit.log

Default: auditing is not enabled.'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'Edit the API server pod specification file /etc/kubernetes/manifests/kube-apiserver.yaml on the master node and set the --audit-log-maxage parameter to at least 30 or as an appropriate number of days: 
--audit-log-maxage=30

Default: auditing is not enabled.'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'Edit the API server pod specification file /etc/kubernetes/manifests/kube-apiserver.yaml on the master node and set the --audit-log-maxbackup parameter to at least 10 or to an appropriate value. 
--audit-log-maxbackup=10

Default: auditing is not enabled.'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'Edit the API server pod specification file /etc/kubernetes/manifests/kube-apiserver.yaml on the master node and set the --audit-log-maxsize parameter to an appropriate size in MB. For example, to set it as 100 MB: 
--audit-log-maxsize=100

Default: auditing is not enabled.'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'Edit the API server pod specification file /etc/kubernetes/manifests/kube-apiserver.yaml and set the below parameter as appropriate between 60 and 300 seconds and if needed. For example, 
--request-timeout=300s

Default: 60 seconds.'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'Edit the API server pod specification file /etc/kubernetes/manifests/kube-apiserver.yaml on the master node and set the below parameter. 
--service-account-lookup=true 
Alternatively, you can delete the --service-account-lookup parameter from this file so that the default takes effect.

Default: true.'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'Edit the API server pod specification file /etc/kubernetes/manifests/kube-apiserver.yaml on the master node and set the --service-account-key-file parameter to the public key file for service accounts: 
--service-account-key-file=<filename>
The corresponding private key must be provided to the controller manager. You would need to securely maintain the key file and rotate the keys based on your organization'\''s key rotation policy.

Default: --tls-private-key-file is used.'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'Follow the Kubernetes documentation and set up the TLS connection between the apiserver and etcd. Then, edit the API server pod specification file /etc/kubernetes/manifests/kube-apiserver.yaml on the master node and set the etcd certificate and key file parameters. 
--etcd-certfile=<path/to/client-certificate-file>
--etcd-keyfile=<path/to/client-key-file>

Default: --etcd-certfile and --etcd-keyfile arguments are not set.'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'Follow the Kubernetes documentation and set up the TLS connection on the apiserver. Then, edit the API server pod specification file /etc/kubernetes/manifests/kube-apiserver.yaml on the master node and set the TLS certificate and private key file parameters. 
--tls-cert-file=<path/to/tls-certificate-file>
--tls-private-key-file=<path/to/tls-key-file>

Default: if HTTPS serving is enabled a self-signed certificate and key will be generated and used.'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'Follow the Kubernetes documentation and set up the TLS connection on the apiserver. Then, edit the API server pod specification file /etc/kubernetes/manifests/kube-apiserver.yaml on the master node and set the client certificate authority file. 
--client-ca-file=<path/to/client-ca-file>

Default: not set.'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'Follow the Kubernetes documentation and set up the TLS connection between the apiserver and etcd. Then, edit the API server pod specification file /etc/kubernetes/manifests/kube-apiserver.yaml on the master node and set the etcd certificate authority file parameter. 
--etcd-cafile=<path/to/ca-file>

Default: not set.'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'Follow the Kubernetes documentation and configure a EncryptionConfig file. Then, edit the API server pod specification file /etc/kubernetes/manifests/kube-apiserver.yaml on the master node and set the --encryption-provider-config parameter to the path of that file: 
--encryption-provider-config=</path/to/EncryptionConfig/File>

Default: not set.'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'Follow the Kubernetes documentation and configure a EncryptionConfig file. In this file, choose aescbc, kms or secretbox as the encryption provider.

Default: no encryption provider is set.'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'Edit the API server pod specification file /etc/kubernetes/manifests/kube-apiserver.yaml on the master node and configure the tls-cipher-suites parameter to needed set of strong cryptographic ciphers.
Preferred values: TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384, TLS_CHACHA20_POLY1305_SHA256, TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA, TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA, TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384, TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305, TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256, TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA, TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA, TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384, TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305, TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256, TLS_RSA_WITH_AES_128_CBC_SHA, TLS_RSA_WITH_AES_128_GCM_SHA256, TLS_RSA_WITH_AES_256_CBC_SHA, TLS_RSA_WITH_AES_256_GCM_SHA384.
Insecure values: TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256, TLS_ECDHE_ECDSA_WITH_RC4_128_SHA, TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA, TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256, TLS_ECDHE_RSA_WITH_RC4_128_SHA, TLS_RSA_WITH_3DES_EDE_CBC_SHA, TLS_RSA_WITH_AES_128_CBC_SHA256, TLS_RSA_WITH_RC4_128_SHA.

Default: a wide range of default Go cipher suites will be used.'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'Edit the Controller Manager pod specification file /etc/kubernetes/manifests/kube-controller-manager.yaml on the master node and set the --terminated-pod-gc-threshold to an appropriate threshold (recommended: 1000 or less but more than 0), for example: 
--terminated-pod-gc-threshold=10

Default: 12500.'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'Edit the Controller Manager pod specification file /etc/kubernetes/manifests/kube-controller-manager.yaml on the master node and set the below parameter. 
--profiling=false

Default: true.'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'Edit the Controller Manager pod specification file /etc/kubernetes/manifests/kube-controller-manager.yaml on the master node to set the below parameter. 
--use-service-account-credentials=true

Default: false.'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'Edit the Controller Manager pod specification file /etc/kubernetes/manifests/kube-controller-manager.yaml on the master node and set the --service-account-privatekey-file parameter to the private key file for service accounts. 
--service-account-private-key-file=<filename>

Default: not set.'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'Edit the Controller Manager pod specification file /etc/kubernetes/manifests/kube-controller-manager.yaml on the master node and set the --root-ca-file parameter to the certificate bundle file. 
--root-ca-file=<path/to/file>

Default: not set.'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'Edit the Controller Manager pod specification file /etc/kubernetes/manifests/kube-controller-manager.yaml on the master node and set RotateKubeletServerCertificate argument in the --feature-gates parameter to true or leave default (unset). 
--feature-gates=RotateKubeletServerCertificate=true

Default: RotateKubeletServerCertificate is set to true.'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'Edit the Controller Manager pod specification file /etc/kubernetes/manifests/kube-controller-manager.yaml on the master node and ensure the 127.0.0.1 value for the --bind-address parameter.

Default: 0.0.0.0.'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'Edit the Scheduler pod specification file /etc/kubernetes/manifests/kube-scheduler.yaml file on the master node and set the below parameter. 
--profiling=false

Default: true.'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'Edit the Scheduler pod specification file /etc/kubernetes/manifests/kubescheduler.yaml on the master node and ensure the correct value for the --bind-address parameter.

Default: 0.0.0.0.'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'Follow the etcd service documentation and configure TLS encryption. Then, edit the etcd pod specification file /etc/kubernetes/manifests/etcd.yaml on the master node and set the below parameters. 
--cert-file=</path/to/ca-file> 
--key-file=</path/to/key-file>

Default: not set.'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'Edit the etcd pod specification file /etc/kubernetes/manifests/etcd.yaml on the master node and set the below parameter. 
--client-cert-auth=true

Default: the etcd service can be queried by unauthenticated clients.'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'Edit the etcd pod specification file /etc/kubernetes/manifests/etcd.yaml on the master node and either remove the --auto-tls parameter or set it to false. 
--auto-tls=false

Default: false.'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'Follow the etcd service documentation and configure peer TLS encryption as appropriate for your etcd cluster. 
Then, edit the etcd pod specification file /etc/kubernetes/manifests/etcd.yaml on the master node and set the below parameters. 
--peer-cert-file=</path/to/peer-cert-file>
--peer-key-file=</path/to/peer-key-file>

Default: peer communication over TLS is not configured.'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'Edit the etcd pod specification file /etc/kubernetes/manifests/etcd.yaml on the master node and set the below parameter. 
--peer-client-cert-auth=true

Default: false.'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'Edit the etcd pod specification file /etc/kubernetes/manifests/etcd.yaml on the master node and either remove the --peer-auto-tls parameter or set it to false. 
--peer-auto-tls=false

Default: false.'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'Follow the etcd documentation and create a dedicated certificate authority setup for the etcd service. 
Then, edit the etcd pod specification file /etc/kubernetes/manifests/etcd.yaml on the master node and set the below parameter. 
--trusted-ca-file=</path/to/ca-file>

Default: no etcd certificate is created and used.'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'It is not possible to fully disable client certificate use within a cluster as it is used for component to component authentication. Do not use certificate authentication for client authentication. Alternative mechanisms provided by Kubernetes such as the use of OIDC should be implemented in place of client certificates.'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'Create an audit policy file for your cluster and configure the --audit-policy-file parameter for kube-apiserver.

Default: no auditing.'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'Consider modification of the audit policy in use on the cluster to include these items, at a minimum.

Default: no auditing.'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'Identify all clusterrolebindings to the cluster-admin role. Check if they are used and if they need this role or if they could use a role with fewer privileges. 
Where possible, first bind users to a lower privileged role and then remove the clusterrolebinding to the cluster-admin role: 
kubectl delete clusterrolebinding [name]

Default: a single clusterrolebinding called cluster-admin is provided with the system:masters group as its principal.'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'Where possible, remove get, list and watch access to secret objects in the cluster.'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'Where possible, remove create access to pod objects in the cluster.'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'Create explicit service accounts wherever a Kubernetes workload requires specific access to the Kubernetes API server.'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'Modify the configuration of each default service account to include the value automountServiceAccountToken: false.

Default: true.'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'Modify the definition of service accounts which do not need to mount service account tokens to disable it.

Default: true (all pods get a service account token mounted in them).'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'Modify the definition of pods which do not need to mount service account tokens to disable it.

Default: true (all pods get a service account token mounted in them).'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'Where possible replace any use of wildcards in clusterroles and roles with specific objects or actions.'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'Restrict admission of privileged containers:
1. If PodSecurityPolicy is used:
Create a PSP as described in the Kubernetes documentation, ensuring that the .spec.privileged field is omitted or set to false. If you need to run privileged containers, this should be defined in a separate PSP and you should carefully check RBAC controls to ensure that only limited service accounts and users are given permission to access that PSP.
Default: false.
2. If Pod Security Admission is used: 
Apply Baseline or Restricted policy in enforce mode to every namespace, excluding where it is strictly neccessary. Example:
kubectl label --dry-run=server --overwrite ns example-namespace pod-security.kubernetes.io/enforce=restricted
kubectl label --overwrite ns example-namespace pod-security.kubernetes.io/enforce=restricted
3. Alternatively a 3rd party admission plugin can be used, such as Kubewarden, Kyverno, OPA Gatekeeper.'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'Restrict admission of containers wishing to share the host process ID namespace:
1. If PodSecurityPolicy is used:
Create a PSP as described in the Kubernetes documentation, ensuring that the .spec.hostPID field is omitted or set to false. If you need to run containers which require hostPID, this should be defined in a separate PSP and you should carefully check RBAC controls to ensure that only limited service accounts and users are given permission to access that PSP.
Default: false.
2. If Pod Security Admission is used: 
Apply Baseline or Restricted policy in enforce mode to every namespace, excluding where it is strictly neccessary. Example:
kubectl label --dry-run=server --overwrite ns example-namespace pod-security.kubernetes.io/enforce=restricted
kubectl label --overwrite ns example-namespace pod-security.kubernetes.io/enforce=restricted
3. Alternatively a 3rd party admission plugin can be used, such as Kubewarden, Kyverno, OPA Gatekeeper.'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'Restrict admission of containers wishing to share the host IPC namespace:
1. If PodSecurityPolicy is used:
Create a PSP as described in the Kubernetes documentation, ensuring that the .spec.hostIPC field is omitted or set to false. If you have a requirement to containers which require hostIPC, this should be defined in a separate PSP and you should carefully check RBAC controls to ensure that only limited service accounts and users are given permission to access that PSP.
Default: false.
2. If Pod Security Admission is used: 
Apply Baseline or Restricted policy in enforce mode to every namespace, excluding where it is strictly neccessary. Example:
kubectl label --dry-run=server --overwrite ns example-namespace pod-security.kubernetes.io/enforce=restricted
kubectl label --overwrite ns example-namespace pod-security.kubernetes.io/enforce=restricted
3. Alternatively a 3rd party admission plugin can be used, such as Kubewarden, Kyverno, OPA Gatekeeper.'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'Restrict admission of containers wishing to share the host network namespace:
1. If PodSecurityPolicy is used:
Create a PSP as described in the Kubernetes documentation, ensuring that the .spec.hostNetwork field is omitted or set to false. If you have need to run containers which require hostNetwork, this should be defined in a separate PSP and you should carefully check RBAC controls to ensure that only limited service accounts and users are given permission to access that PSP.
Default: false.
2. If Pod Security Admission is used: 
Apply Baseline or Restricted policy in enforce mode to every namespace, excluding where it is strictly neccessary. Example:
kubectl label --dry-run=server --overwrite ns example-namespace pod-security.kubernetes.io/enforce=restricted
kubectl label --overwrite ns example-namespace pod-security.kubernetes.io/enforce=restricted
3. Alternatively a 3rd party admission plugin can be used, such as Kubewarden, Kyverno, OPA Gatekeeper.'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'Restrict admission of privileged containers:
1. If PodSecurityPolicy is used:
Create a PSP as described in the Kubernetes documentation, ensuring that the .spec.allowPrivilegeEscalation field is omitted or set to false. If you have need to run containers which use setuid binaries or require privilege escalation, this should be defined in a separate PSP and you should carefully check RBAC controls to ensure that only limited service accounts and users are given permission to access that PSP.
Default: true.
2. If Pod Security Admission is used: 
Apply Restricted policy in enforce mode to every namespace, excluding where it is strictly neccessary. Example:
kubectl label --dry-run=server --overwrite ns example-namespace pod-security.kubernetes.io/enforce=restricted
kubectl label --overwrite ns example-namespace pod-security.kubernetes.io/enforce=restricted
3. Alternatively a 3rd party admission plugin can be used, such as Kubewarden, Kyverno, OPA Gatekeeper.'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'Restrict admission of root containers:
1. If PodSecurityPolicy is used:
Create a PSP as described in the Kubernetes documentation, ensuring that the .spec.runAsUser.rule is set to either MustRunAsNonRoot or MustRunAs with the range of UIDs not including 0. If you need to run root containers, this should be defined in a separate PSP and you should carefully check RBAC controls to ensure that only limited service accounts and users are given permission to access that PSP.
2. If Pod Security Admission is used: 
Apply Restricted policy in enforce mode to every namespace, excluding where it is strictly neccessary. Example:
kubectl label --dry-run=server --overwrite ns example-namespace pod-security.kubernetes.io/enforce=restricted
kubectl label --overwrite ns example-namespace pod-security.kubernetes.io/enforce=restricted
3. Alternatively a 3rd party admission plugin can be used, such as Kubewarden, Kyverno, OPA Gatekeeper.'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'Restrict admission of containers with the NET_RAW capability:
1. If PodSecurityPolicy is used:
Include either NET_RAW or ALL to the .spec.requiredDropCapabilities attribute for all PSPs where these capabilities are not necessary/ Ensure that at least one PSP exist with NET_RAW or ALL in the .spec.requiredDropCapabilities attrubite. If you need to run containers with these capabilities, this should be defined in a separate PSP and you should carefully check RBAC controls to ensure that only limited service accounts and users are given permission to access that PSP.
2. If Pod Security Admission is used: 
Apply Baseline or Restricted policy in enforce mode to every namespace, excluding where it is strictly neccessary. Example:
kubectl label --dry-run=server --overwrite ns example-namespace pod-security.kubernetes.io/enforce=restricted
kubectl label --overwrite ns example-namespace pod-security.kubernetes.io/enforce=restricted
3. Alternatively a 3rd party admission plugin can be used, such as Kubewarden, Kyverno, OPA Gatekeeper.'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'Restrict admission of containers with added capabilities:
1. If PodSecurityPolicy is used:
Ensure that defaultAddCapabilities or allowedCapabilities is not present in PSPs for the cluster unless it is set to an empty array and at least one PSP exists with defaultAddCapabilities and allowedCapabilities set to empty arrays. If you need to run containers with additional capabilities, this should be defined in a separate PSP and you should carefully check RBAC controls to ensure that only limited service accounts and users are given permission to access that PSP.
2. If Pod Security Admission is used: 
Apply Restricted policy in enforce mode to every namespace, excluding where it is strictly neccessary. Example:
kubectl label --dry-run=server --overwrite ns example-namespace pod-security.kubernetes.io/enforce=restricted
kubectl label --overwrite ns example-namespace pod-security.kubernetes.io/enforce=restricted
3. Alternatively a 3rd party admission plugin can be used, such as Kubewarden, Kyverno, OPA Gatekeeper.'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'Review the use of capabilities in applications running on your cluster. Where a namespace contains applications which do not require any Linux capabilities to operate consider adding a policy which forbids the admission of containers which do not drop all capabilities.'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'If the CNI plugin in use does not support network policies, consideration should be given to making use of a different plugin, or finding an alternate mechanism for restricting traffic in the Kubernetes cluster.'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'For each namespace create (if not exist) Network Policy selecting all pods in that namespace for ingress traffic rules. Default deny policy can be used, example:
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-ingress
spec:
  podSelector: {}
  policyTypes:
  - Ingress

Add needed rules or/and Network Policies for permitted ingress traffic.

Default: all traffic is permitted.'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'For each namespace create (if not exist) Network Policy selecting all pods in that namespace for egress traffic rules. Default deny policy can be used, example:
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-egress
spec:
  podSelector: {}
  policyTypes:
  - Egress

Add needed rules or/and Network Policies for permitted egress traffic.

Default: all traffic is permitted.'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'If possible, rewrite application code to read secrets from mounted secret files, rather than from environment variables.

Default: secrets are not defined.'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'Refer to the secrets management options offered by your cloud provider or a third-party secrets management solution.

Default: no external secret management is configured.'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'Follow the Kubernetes documentation and setup image provenance.

Default: image provenance is not set.'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'Follow the documentation and create namespaces for objects in your deployment as you need them.

Default: Kubernetes starts with some initial namespaces:
1. default - The default namespace for objects with no other namespace
2. kube-system - The namespace for objects created by the Kubernetes system
3. kube-node-lease - Namespace used for node heartbeats
4. kube-public - Namespace used for public information in a cluster'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'in versions v1.19 and higher seccomp profile is configured by the securityContext.seccompProfile field for pods and containers. Additionally default seccomp profile may be enabled with the kubelet SeccompDefault feature gate (enabled by default in versions v1.25 and higher) in combination with the corresponding --seccomp-default command line flag. More info can be viewed on https://kubernetes.io/docs/tutorials/security/seccomp/ .
An example pod configuration is as below:
securityContext:
  seccompProfile:
    type: RuntimeDefault
In older versions Seccomp is an alpha feature. By default, all alpha features are disabled. So, you would need to enable it in the apiserver by passing "--feature-gates=AllAlpha=true" argument. Set the kube-apiserver start parameter to "--feature-gates=AllAlpha=true" and restart the kube-apiserver. Then use annotations to enable the docker/default seccomp profile in your pod definitions. An example is as below: 
apiVersion: v1 
kind: Pod 
metadata: 
 name: trustworthy-pod 
annotations: 
 seccomp.security.alpha.kubernetes.io/pod: docker/default 
spec: containers: 
 - name: trustworthy-container 
image: sotrustworthy:latest'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'Follow the Kubernetes documentation and apply security contexts to your pods.

Default: no security contexts are automatically applied to pods.'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'Ensure that namespaces are created to allow for appropriate segregation of Kubernetes resources and that all new resources are created in a specific namespace.'
read -n 1 -p "Press Enter to continue..."



