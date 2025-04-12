#!/bin/bash

# Tạo thư mục chứa chứng chỉ nếu chưa tồn tại
mkdir -p certs

# Tạo chứng chỉ SSL tự ký cho môi trường phát triển
dotnet dev-certs https -ep ./certs/aspnetapp.pfx -p password

# Tin tưởng chứng chỉ trên máy local
dotnet dev-certs https --trust

echo "Đã tạo chứng chỉ SSL cho môi trường phát triển"