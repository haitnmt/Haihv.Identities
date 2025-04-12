# Haihv.Identities
Hệ thống dịch vụ xác thực tích hợp với LDAP

## Giới thiệu
Haihv.Identities là một hệ thống API xác thực hiện đại được phát triển bằng ASP.NET Core, cung cấp các dịch vụ xác thực và quản lý danh tính người dùng thông qua tích hợp với LDAP (Lightweight Directory Access Protocol).

### Tính năng chính
- **Xác thực người dùng**: Hỗ trợ xác thực người dùng thông qua LDAP với tên đăng nhập và mật khẩu
- **Quản lý token**: Sử dụng JWT (JSON Web Token) cho xác thực và ủy quyền
- **Refresh token**: Hỗ trợ cơ chế refresh token để duy trì phiên đăng nhập
- **Bảo mật**: Phát hiện và ngăn chặn các nỗ lực đăng nhập không hợp lệ, khóa IP sau nhiều lần đăng nhập thất bại
- **Quản lý nhóm**: Hỗ trợ quản lý nhóm người dùng thông qua LDAP
- **Bộ nhớ đệm**: Sử dụng Valkey (thay thế cho Redis) để lưu trữ thông tin phiên và token
- **Ghi nhật ký**: Tích hợp Serilog để ghi nhật ký hoạt động hệ thống

### Công nghệ sử dụng
- **ASP.NET Core 9.0**: Framework phát triển API hiện đại
- **LDAP**: Giao thức truy cập thư mục nhẹ để xác thực và quản lý người dùng
- **JWT**: Chuẩn mở để truyền thông tin an toàn giữa các bên
- **Valkey**: Bộ nhớ đệm phân tán thay thế cho Redis
- **Serilog**: Framework ghi nhật ký linh hoạt
- **Docker**: Đóng gói ứng dụng trong container để triển khai dễ dàng

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

## API Endpoints

### Xác thực và Quản lý Phiên

| Endpoint | Phương thức | Mô tả | Yêu cầu xác thực |
|----------|-------------|-------|------------------|
| `/api/login` | POST | Đăng nhập với tên người dùng và mật khẩu | Không |
| `/api/refreshToken` | POST | Làm mới token truy cập bằng refresh token | Không |
| `/api/logout` | POST | Đăng xuất và hủy token hiện tại | Không |
| `/api/verify` | POST | Xác minh tính hợp lệ của token | Có |

### Cấu trúc Dữ liệu

#### Đăng nhập
```json
{
  "username": "tên_đăng_nhập",
  "password": "mật_khẩu",
  "rememberMe": true
}
```

### Cấu hình LDAP

Hệ thống sử dụng cấu hình LDAP được định nghĩa trong file `appsettings.json`:

```json
"LDAP": {
  "Host": "host",
  "Port": 389,
  "Domain": "domain",
  "DomainFullname": "domain.fullname",
  "Organizational": "Organizational",
  "SearchBase": "dc=domein,dc=fullname",
  "RootGroupDn": "CN=base,OU=base,DC=domain,DC=fullname",
  "AdminGroupDn": "CN=admin,OU=admin,DC=domain,DC=fullname",
  "AdminPrincipalName": "admin@domain.fullname",
  "AdminPassword": "password",
  "DefaultSyncDelay": 300
}
```

### Bảo mật

Hệ thống sử dụng JWT để xác thực và ủy quyền. Cấu hình JWT được định nghĩa trong file `appsettings.json`:

```json
"JwtOptions": {
  "SecretKey": "your_secret_key",
  "Issuer": "https://localhost:5001",
  "Audience": "https://localhost:5001",
  "ExpireMinutes": 10,
  "ExpireRefreshTokenDays": 7
}
```

## Kiến trúc hệ thống

### Tổng quan
Hệ thống được xây dựng theo kiến trúc Clean Architecture với các lớp rõ ràng:

1. **API Layer**: Xử lý các yêu cầu HTTP và phản hồi
2. **Service Layer**: Chứa logic nghiệp vụ chính
3. **Data Access Layer**: Tương tác với LDAP và bộ nhớ đệm

### Các thành phần chính

- **LdapContext**: Quản lý kết nối đến máy chủ LDAP
- **UserLdapService**: Quản lý thông tin người dùng từ LDAP
- **GroupLdapService**: Quản lý thông tin nhóm từ LDAP
- **AuthenticateLdapService**: Xử lý xác thực người dùng
- **TokenProvider**: Quản lý việc tạo và xác thực JWT
- **HybridCache**: Lưu trữ thông tin phiên và token

### Luồng xác thực

1. Người dùng gửi thông tin đăng nhập (tên đăng nhập và mật khẩu)
2. Hệ thống xác thực thông tin với máy chủ LDAP
3. Nếu xác thực thành công, hệ thống tạo JWT và refresh token
4. JWT được trả về cho người dùng, refresh token được lưu trong cookie
5. Người dùng sử dụng JWT cho các yêu cầu tiếp theo
6. Khi JWT hết hạn, người dùng có thể sử dụng refresh token để lấy JWT mới

## Hướng dẫn phát triển

### Cài đặt môi trường phát triển

1. Cài đặt .NET 9.0 SDK
2. Cài đặt Docker và Docker Compose
3. Clone repository

### Chạy ứng dụng trong môi trường phát triển

```bash
# Di chuyển đến thư mục dự án
cd src/Haihv.Identity.Ldap.Api

# Khôi phục các gói NuGet
dotnet restore

# Chạy ứng dụng
dotnet run
```

### Cấu trúc thư mục

- **src/Haihv.Identity.Ldap.Api**: Mã nguồn chính của API
  - **Entities**: Các đối tượng dữ liệu
  - **Services**: Các dịch vụ xử lý logic nghiệp vụ
  - **Features**: Các tính năng của API (theo mô hình CQRS)
  - **Extensions**: Các phương thức mở rộng
  - **Interfaces**: Các giao diện

### Đóng góp

Nếu bạn muốn đóng góp vào dự án, vui lòng:

1. Fork repository
2. Tạo nhánh tính năng mới (`git checkout -b feature/amazing-feature`)
3. Commit các thay đổi của bạn (`git commit -m 'Add some amazing feature'`)
4. Push lên nhánh của bạn (`git push origin feature/amazing-feature`)
5. Mở Pull Request
