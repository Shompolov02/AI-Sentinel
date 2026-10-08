FROM nginxinc/nginx-unprivileged:1.27-alpine

USER root
RUN rm -f /var/log/nginx/access.log \
    && touch /var/log/nginx/access.log \
    && chown -R 101:0 /var/log/nginx
COPY deploy/nginx/default.conf.template /etc/nginx/templates/default.conf.template
USER 101
