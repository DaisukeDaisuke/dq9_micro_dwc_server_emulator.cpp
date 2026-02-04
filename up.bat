docker-compose down -v --remove-orphans
docker volume prune -f
docker compose up -d --build
pause
