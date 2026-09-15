FROM python:3.12-slim

ARG TARGETARCH

# kubectl AND oc - k10.py picks whichever one matches the cluster this app
# is actually running against at runtime (oc on OpenShift, kubectl
# everywhere else - see k10._kubectl_binary), same pattern as
# cpouthier/malware-scan's own Dockerfile.
RUN apt-get update && apt-get install -y --no-install-recommends \
      curl ca-certificates && \
    curl -fsSL "https://dl.k8s.io/release/$(curl -fsSL https://dl.k8s.io/release/stable.txt)/bin/linux/${TARGETARCH}/kubectl" \
      -o /usr/local/bin/kubectl && \
    chmod +x /usr/local/bin/kubectl && \
    OC_ARCH="$( [ "${TARGETARCH}" = "arm64" ] && echo arm64 || echo x86_64 )" && \
    curl -fsSL "https://mirror.openshift.com/pub/openshift-v4/${OC_ARCH}/clients/ocp/stable/openshift-client-linux.tar.gz" \
      | tar -xz -C /usr/local/bin oc && \
    chmod +x /usr/local/bin/oc && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY app/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app/ .

# Where settings.json and alerts.db live - a PVC mounted here in k8s (see
# helm/kasten-alerting/templates/deployment.yaml), so both survive a pod
# restart/redeploy.
ENV DATA_DIR=/data

EXPOSE 8000
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
