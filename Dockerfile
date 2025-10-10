FROM gcr.io/distroless/static-debian11:nonroot
ENTRYPOINT ["/baton-okta-ciam-workforce"]
COPY baton-okta-ciam-workforce /