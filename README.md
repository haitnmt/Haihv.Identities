# Haihv.Identities
Các dịch vụ xác thực

## Hướng dẫn chạy ứng dụng với Docker Compose

### Yêu cầu
- Docker và Docker Compose

### Các bước thực hiện

1. Tạo chứng chỉ SSL cho môi trường phát triển:
```bash
# Cấp quyền thực thi cho script
chmod +x create-dev-cert.sh

# Chạy script tạo chứng chỉ
./create-dev-cert.sh
```

2. Khởi động ứng dụng với Docker Compose (sử dụng image đã được build bởi workflows):
```bash
docker-compose up -d
```

3. Truy cập ứng dụng:
- API: https://localhost:8080

4. Dừng ứng dụng:
```bash
docker-compose down
```

### Lưu ý
- Ứng dụng sử dụng image đã được build bởi workflows: `haitnmt/ldap-api:latest`
- Sử dụng Valkey thay vì Redis cho bộ nhớ cache
- API chạy trên cổng HTTPS 8080
- Sử dụng chứng chỉ SSL tự ký cho môi trường phát triển
- Đã cấu hình để bỏ qua xác thực SSL không chính thức
- Kết nối đến Valkey thông qua tên dịch vụ Docker (valkey:6379) thay vì localhost
- Cấu hình Redis được ghi đè thông qua biến môi trường trong docker-compose.yml
