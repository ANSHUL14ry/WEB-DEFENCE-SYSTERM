FROM ghcr.io/coreruleset/coraza-crs:caddy-alpine

USER root
# Create directory for structured WAF audit logs and set permissions
RUN mkdir -p /var/log/coraza /opt/coraza/config.d && chown -R caddy:caddy /var/log/coraza /opt/coraza/config.d

# Copy custom WAF configuration overrides
COPY config.d/ /opt/coraza/config.d/
RUN chown -R caddy:caddy /opt/coraza/config.d/

USER caddy

EXPOSE 8080

HEALTHCHECK --interval=10s --timeout=5s --start-period=5s --retries=3 \
  CMD curl -f http://localhost:8080/health || exit 1
