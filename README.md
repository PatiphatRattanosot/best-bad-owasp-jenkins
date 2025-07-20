docker compose down

docker compose up -d

http://localhost:8383

http://localhost:3000

docker pull zaproxy/zap-stable

docker run -t zaproxy/zap-stable zap-full-scan.py -t http://host.docker.internal:3000
