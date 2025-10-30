#!/bin/sh
echo "🔐 Setting TLS cert permissions..."
if [ -f /etc/ssl/certs/tls.key ]; then
  chmod 600 /etc/ssl/certs/tls.key
  chmod 644 /etc/ssl/certs/tls.crt
fi

echo "🚀 Starting app..."
exec "$@"

