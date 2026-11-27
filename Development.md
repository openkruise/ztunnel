# Development

## Contribute

Open pull requests against `master`.

Copyright checks compare the source tree with the pinned Istio 1.29.5 baseline,
independently of this repository's commit history. Fetch that baseline once in a
fresh clone before running the checks:

```shell
git fetch --no-tags --depth=1 https://github.com/istio/ztunnel.git refs/tags/1.29.5
make BUILD_WITH_CONTAINER=0 lint-copyright-kruise
```

Before you submit your PRs, please ensure no error with following command:

* `make presubmit`
* `make test`

To do more comprehensive testing, please refer to [Local Testing](#local-testing).

## Local Testing

SOCKS5 is available only in test builds (`cfg(test)` or the `testing` feature).
Integration tests enable it through `Config::socks5_addr`; normal builds have no
SOCKS5 listener or configuration. `UNSTABLE_ENABLE_SOCKS5` is no longer supported.

Along with running in a Kubernetes, ztunnel can be run locally for development purposes.

This doc covers ztunnel specifically, for general Istio local development see
[Local Istio Development](https://github.com/howardjohn/local-istio-development).

### Overrides

There are a variety of config options that can be used to replace components with mocked ones:

* `FAKE_CA="true"`: this will use self-signed fake certificates, eliminating a dependency on a CA
* `XDS_ADDRESS=""`: disables XDS client completely
* `LOCAL_XDS_PATH=./examples/localhost.yaml`: read XDS config from a file.
* `CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUNNER="sudo -E"`: have cargo run as sudo
* `PROXY_MODE=dedicated`: Dedicated mode is the single-tenant proxy mode and is strongly recommended for local development, as it works for 95% of cases and doesn't require manually constructing Linux network namespaces to use.

The following command (with `--no-default-features` if you have FIPS disabled) can be used to run entirely locally, without a Kubernetes or Istiod dependency.

```shell
FAKE_CA="true" \
XDS_ADDRESS="" \
LOCAL_XDS_PATH=./examples/localhost.yaml \
CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUNNER="sudo -E" \
PROXY_MODE=dedicated \
PROXY_WORKLOAD_INFO=default/local/default \
cargo run --features testing
```

### Local gateway mode

`DISCOVERY_MODE=local` starts a single-workload proxy from environment variables.
It does not open an xDS connection. Intercepted TCP connections are sent to the
configured egress gateway over mTLS HBONE, retaining their original destination.
The gateway applies policy.

```shell
DISCOVERY_MODE=local \
WORKLOAD_ID=instance-123 \
WORKLOAD_IDENTITY=spiffe://agentio.local/workloads/instance-123 \
INSTANCE_IP=10.0.0.10 \
SANDBOX_ID=sandbox-123 \
EGRESS_GATEWAY_ADDRESS=egress.example.com:15008 \
EGRESS_GATEWAY_IDENTITY=spiffe://agentio.local/gateways/porter \
CA_ADDRESS=https://agentiod.example.com:15012 \
CA_ROOT_CA=/etc/agentio/root-cert.pem \
AUTH_TOKEN=/run/agentio/bootstrap.token \
./ztunnel
```

| Variable | Meaning |
| --- | --- |
| `WORKLOAD_ID` | Required stable identifier of the local workload. |
| `WORKLOAD_IDENTITY` | Required SPIFFE identity for the workload certificate. |
| `INSTANCE_IP` | Workload IP; defaults to `127.0.0.1`. |
| `SANDBOX_ID` | Optional fixed Sandbox UID included in HBONE requests; mutually exclusive with `ENABLE_SANDBOX_MANAGER`. |
| `EGRESS_GATEWAY_ADDRESS` | Required IP or DNS hostname with a nonzero port; IPv6 uses `[address]:port`. |
| `EGRESS_GATEWAY_IDENTITY` | Required SPIFFE identity expected in the gateway certificate. |
| `CA_ADDRESS` | Required certificate service endpoint. |
| `CA_ROOT_CA`, `AUTH_TOKEN`, `SECRET_TTL` | Existing CA trust, bootstrap credential and requested certificate lifetime settings. |
| `WORKLOAD_IDENTITY_DIR` | Optional absolute directory for the instance certificate and private key; enables certificate authentication for subsequent CA requests. |
| `ENABLE_SANDBOX_MANAGER` | Enables preparation after startup using agentiod's Sandbox Get RPC instead of a fixed `SANDBOX_ID`. |

Identities are complete SPIFFE URIs; their paths do not require a namespace or
ServiceAccount. `WORKLOAD_ID` selects the local workload by UID independently of
its certificate identity. Local mode ignores `PROXY_WORKLOAD_INFO` and does not
require Pod metadata. The CA must authenticate the bootstrap credential and
authorize the requested identity. Non-Kubernetes
credentials require the corresponding CA authentication and authorization
adapter; selecting local mode does not add that adapter to agentiod.
The gateway must already be able to resolve and validate the Sandbox's binding
to the authenticated workload; setting `SANDBOX_ID` does not register it.

The bootstrap adapters meet at the proxy state: local configuration creates a
workload with its UID and explicit principal, while the xDS adapter translates
legacy namespace/ServiceAccount fields into a SPIFFE identity. The shared proxy
looks up its workload through `WorkloadReference` (UID or Kubernetes metadata)
and obtains certificates using `Workload::identity()`. The identity module treats
SPIFFE paths as opaque; TLS still checks the trust domain and the expected peer
identity. Certificate acquisition, renewal, HBONE forwarding and connection
pools are shared by both modes. Existing xDS wire formats remain compatible.

Local mode defaults to `PROXY_MODE=dedicated` and binds listeners in the process's
current network namespace. The external runtime owns network setup and transparent
traffic redirection. Its rules must exempt ztunnel's own traffic, including CA and
gateway connections, for example by process UID. Merely starting the listener does
not capture application traffic.

Startup obtains the first workload certificate before starting the proxy.
Certificate renewal uses the existing secret manager. Every local CA response
must match the configured SPIFFE identity. Gateway connection or
identity verification failures close the proxied connection without direct
fallback. Only the workload's own certificate is requested.

DNS capture defaults off in this mode; resolving a DNS-named gateway still uses
the process's resolver. No local TrafficPolicy is installed. Local mode uses a
fixed Sandbox binding by default, and rejects `XDS_ON_DEMAND`, `LOCAL_XDS` and
`LOCAL_XDS_PATH`.
Other than certificate renewal and gateway DNS resolution, bootstrap configuration
is fixed until restart.

### Standalone workload credentials and preparation

`WORKLOAD_IDENTITY_DIR=/var/lib/ztunnel/identity` enables persistent instance
credentials. The first request uses `AUTH_TOKEN`; subsequent CA requests use
the current workload certificate for mTLS authentication and omit the bootstrap
Token. The CA must support this authentication flow on the existing
`IstioCertificateService/CreateCertificate` RPC. This change does not add an
agentiod authenticator or enrollment endpoint.

In this mode the issued certificate must carry the Agentio WorkloadIdentity
extension, with a nonempty registry and a UID matching `WORKLOAD_ID`. Its SAN,
validity and key pair are checked before publishing the credentials. A single
`identity.json` contains the private key and certificate chain, is written with
mode 0600, and is replaced atomically. Keep this directory private to the
workload instance. Restart restores a valid identity without using the Token;
an expired identity requires a new bootstrap credential. Malformed, mismatched
or unreadable identity files fail startup instead of being silently replaced.
Without this setting, existing Token-based renewal remains available.

For preparation after a workload has already started, omit `SANDBOX_ID` and set
`ENABLE_SANDBOX_MANAGER=true`. The proxy becomes ready after obtaining its own
certificate and starting its listeners, without querying Sandbox configuration.
A trusted launcher then calls the existing `SandboxNetwork/PrepareSandbox` RPC.
The management endpoint retains its existing loopback/mTLS configuration; use
the management mTLS identity allowlist when exposing it beyond the trusted host.

Local preparation calls `SandboxQueryService/GetSandbox` at `CA_ADDRESS` using
the workload certificate and `CA_ROOT_CA`; it requires a real CA endpoint and
cannot be combined with `FAKE_CA`. The request selects the Sandbox UID;
the response must use the same UID and bind it to this workload. The query
protocol is shared with the Agentio Sandbox Get clients. agentiod still needs
to authenticate and authorize the standalone workload and resolve its scope.
ztunnel does not contact the external Sandbox source itself or enforce the
gateway's inline policies.

The Get adapter requires a positive `cache_ttl`, refreshes at half its lifetime,
and reuses its TLS connection until credentials or trust roots change. New
connections only read the cached binding. An unbound, expired or differently
bound registered Sandbox blocks new connections; transient query errors retain
the previous binding only until its TTL expires. Already established connections
are not terminated by a binding update. Prepare confirms local preparation, not
gateway/EPE readiness. A registration survives process restart and is revalidated
through Get. A different Sandbox ID still requires a fresh proxy registration;
pool recycling and explicit unbinding are outside this change.

The default xDS preparation path uses the same `SandboxLookup` interface and
continues consuming accepted push/on-demand resources without TTL polling.

`DISCOVERY_MODE=xds` is the default and preserves the existing discovery behavior,
including the development overrides above. In local mode `XDS_ADDRESS` and the
mesh discovery address do not create a discovery connection; configure
`CA_ADDRESS` explicitly.

### In-pod mode setup

Create a netns for your "pod" (in this case, just a network namespace):

```shell
ip netns add pod1
ip -n pod1 link set lo up

# veth device
ip link add pod1 type veth peer name pod1-eth0
# move one end to the pod
ip link set pod1-eth0 netns pod1
# configure the veth devices
ip link set pod1 up
ip -n pod1 link set pod1-eth0 up
ip addr add dev pod1 10.0.0.1/24
ip -n pod1 addr add dev pod1-eth0 10.0.0.2/24
```

run fake server with:

```shell
INPOD_UDS=/tmp/ztunnel cargo run --example inpodserver -- pod1
```

(note: In the above command, you can override PROXY_WORKLOAD_INFO default value if you need to match to different values in your `localhost.yaml` file)

run ztunnel (as root) with:

```shell
RUST_LOG=debug PROXY_MODE=shared INPOD_UDS=/tmp/ztunnel FAKE_CA="true" XDS_ADDRESS="" LOCAL_XDS_PATH=./examples/localhost.yaml cargo run --features testing
```

(note: to run ztunnel as root, consider using `export CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUNNER="sudo -E"` so cargo `sudo` the binary)

see the ztunnel sockets:

```shell
ip netns exec pod1 ss -ntlp | grep ztunnel
```

```shell
# redirect traffic to ztunnel
ip netns exec pod1 ./scripts/ztunnel-redirect-inpod.sh
```

To get traffic to work you may need to adjust the IPs in localhost.yaml and start processes in the pod netns.

You can also do `make build FEATURES="--features testing` and use `./out/rust/debug/ztunnel` instead of `cargo run ...`

### In-pod mode with istiod on kind setup

Run ztunnel on from your terminal. With istiod and workloads running in KinD. This works on Linux only.
This approach will have traffic running through your local ztunnel - running outside of k8s as a regular, non-containerized userspace process. This can make certain kinds of debugging and local development flows faster/simpler.

In this setup we will replace ztunnel in one of the nodes. In this example we replace the node named `ambient-worker`.

Created cluster with and add an extraMount to the worker node. This will allow the ztunnel on your laptop
to connect to the cni-socket of the worker node.

```shell
kind create cluster --config=- <<EOF
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
name: ambient
nodes:
- role: control-plane
- role: worker
  extraMounts:
  - hostPath: /tmp/worker1-ztunnel/
    containerPath: /var/run/ztunnel/
- role: worker
containerdConfigPatches:
- |-
  [plugins."io.containerd.grpc.v1.cri".registry.mirrors."localhost:5000"]
    endpoint = ["http://${KIND_REGISTRY_NAME}:5000"]
EOF
```

Now you can install istio ambient and your workloads.
Note that once installed you should see the cni socket appear in `/tmp/worker1-ztunnel/ztunnel.sock`.

Remove ztunnel from the desired node:

```shell
kubectl label node ambient-worker ztunnel=no
kubectl patch daemonset -n istio-system ztunnel --type=merge -p='{"spec":{"template":{"spec":{"affinity":{"nodeAffinity":{"requiredDuringSchedulingIgnoredDuringExecution":{"nodeSelectorTerms":[{"matchExpressions":[{"key":"ztunnel","operator":"NotIn","values":["no"]}]}]}}}}}}}'
```

Get certs and the ztunnel service account token. We do this using a pod with the same service account to the same node.

```shell
kubectl get cm -n istio-system istio-ca-root-cert -o jsonpath='{.data.root-cert\.pem}' > /tmp/istio-root.pem
kubectl create -f - <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: fake-tunnel-worker1
  namespace: istio-system
spec:
  nodeName: ambient-worker
  terminationGracePeriodSeconds: 1
  serviceAccountName: ztunnel
  containers:
  - name: cat-token
    image: ubuntu:22.04
    command:
    - bash
    - -c
    args:
    - "sleep 10000"
    ports:
    - containerPort: 80
    volumeMounts:
    - mountPath: /var/run/secrets/tokens
      name: istio-token
  volumes:
  - name: istio-token
    projected:
      defaultMode: 420
      sources:
      - serviceAccountToken:
          audience: istio-ca
          expirationSeconds: 43200
          path: istio-token
EOF
```

Add localhost as a verified DNS name to istiod

```shell
kubectl set env -n istio-system deploy/istiod ISTIOD_CUSTOM_HOST=localhost
```

Now, port forward istiod, copy over the token and run ztunnel:

```shell
kubectl port-forward -n istio-system svc/istiod 15012:15012 &
mkdir -p ./var/run/secrets/tokens/
kubectl exec -n istio-system fake-tunnel-worker1 -- cat /var/run/secrets/tokens/istio-token > ./var/run/secrets/tokens/istio-token
xargs env <<EOF
INPOD_UDS=/tmp/worker1-ztunnel/ztunnel.sock
CLUSTER_ID=Kubernetes
RUST_LOG=debug
PROXY_MODE="shared"
ISTIO_META_DNS_CAPTURE="true"
ISTIO_META_DNS_PROXY_ADDR="127.0.0.1:15053"
SERVICE_ACCOUNT=ztunnel
POD_NAMESPACE=istio-system
POD_NAME=ztunnel-worker1
CA_ROOT_CA=/tmp/istio-root.pem
XDS_ROOT_CA=/tmp/istio-root.pem
CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUNNER="sudo -E"
cargo run proxy ztunnel
EOF
```

### In-pod mode with real Istiod setup

`ztunnel` can also be run locally but connected to a real Istiod instance.

#### Authentication

Ztunnel authentication for CA requires a pod-bound Service Account token.
This makes local running a bit more complex than normally.

First, you must have at least 1 ztunnel pod running.
See the [instructions](https://github.com/istio/istio/blob/experimental-ambient/CONTRIBUTING.md)
for deploying a ztunnel.

Then the below command will fetch a token:

```shell
source ./scripts/local.sh
ztunnel-local-bootstrap
```

### XDS and CA Setup

While XDS is not a hard requirement due to the static config file, the CA is.
When running locally, ztunnel will automatically connect to an Istiod running on localhost.

Istiod can be run locally as simply as `go run ./pilot/cmd/pilot-discovery discovery`.

### Requests testing setup

Ztunnel expects requests to be redirected with iptables. The following functions can help do this:

* `redirect-user-setup` sets up a new user specified by `$ZTUNNEL_REDIRECT_USER`
* `redirect-to <port>` redirects all traffic from `$ZTUNNEL_REDIRECT_USER` to the given port.
* `redirect-to-clean` removes any iptables rules setup by `redirect-to`
* `redirect-run <cmd>` runs the command as `$ZTUNNEL_REDIRECT_USER`.

To setup redirection logic for all requests from the `iptables1` user to 15001:

```shell
source ./scripts/local.sh
export ZTUNNEL_REDIRECT_USER="iptables1"
redirect-user-setup
redirect-to 15001
```

Finally, requests can be sent through the ztunnel:

```shell
redirect-run curl localhost:8080
```

Without a matching gateway egress policy, the request follows
`curl -> ztunnel (15001) -> localhost:8080` over TCP. A gateway egress policy routes
the connection through the configured gateway over HBONE. Discovering the target
as a Service or Workload does not change the selected route.
