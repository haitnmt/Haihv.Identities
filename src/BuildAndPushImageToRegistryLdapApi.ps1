# Function to read .env file
function Get-EnvVariables {
    $envFile = ".\.env"
    if (Test-Path $envFile) {
        Get-Content $envFile | ForEach-Object {
            if ($_ -match '^\s*([^#][^=]+)=(.*)$') {
                $name = $matches[1].Trim()
                $value = $matches[2].Trim()
                Set-Variable -Name $name -Value $value -Scope Script
            }
        }
    }
    else {
        Write-Host "Warning: .env file not found" -ForegroundColor Yellow
        $TAG=latest
        $REGISTRY_URL=cr.haihv.vn
        $USERNAME=haihv
        $PASSWORD=Abc@1234
        $DOCKERHUB = haitnmt
    }
}

# Function to check if Docker Buildx is available
function Test-Buildx {
    try {
        $buildxOutput = docker buildx version 2>&1
        if ($buildxOutput -match "buildx") {
            return $true
        }
        return $false
    }
    catch {
        return $false
    }
}
# Load environment variables at start
Get-EnvVariables

$ImageName = "ldap-api"
#Lấy thời gian bắt đầu
$startTime = Get-Date
$currentTime = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
Write-Host "[$currentTime] Đang đăng nhập vào registry $REGISTRY_URL..." -ForegroundColor Yellow
${PASSWORD} | docker login ${REGISTRY_URL} -u ${USERNAME} --password-stdin

#Lấy thời gian hiện tại:
$currentTime = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

Write-Host "[$currentTime] Bắt đầu build Api" -ForegroundColor Blue

# Đọc version từ file .csproj latest
$csprojContent = Get-Content -Path ".\Haihv.Identity.Ldap.Api\Haihv.Identity.Ldap.Api.csproj" -Raw
$version = [regex]::Match($csprojContent, '<AssemblyVersion>(.*?)</AssemblyVersion>').Groups[1].Value

$currentTime = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
Write-Host "[$currentTime] Đang build api image verion: $version" -ForegroundColor Yellow

# Kiểm tra xem buildx có sẵn không
$hasBuildx = Test-Buildx
if ($hasBuildx) {
    Write-Host "[$currentTime] Sử dụng Docker Buildx để build image đa nền tảng (multi-platform)" -ForegroundColor Cyan
    
    # Đảm bảo builder mặc định đã được tạo và sử dụng
    docker buildx create --name multiplatform-builder --use --bootstrap 2>&1 | Out-Null
    
    # Build và push trực tiếp lên registry với nhiều nền tảng
    Write-Host "[$currentTime] Đang build và push image đa nền tảng cho $REGISTRY_URL" -ForegroundColor Yellow
    docker buildx build --platform linux/amd64,linux/arm64 -t ${REGISTRY_URL}/${ImageName}:${version} -t ${REGISTRY_URL}/${ImageName}:${TAG} -f src/DockerfileLdapApi . --push
    
    # Build và push trực tiếp lên DockerHub với nhiều nền tảng
    Write-Host "[$currentTime] Đang build và push image đa nền tảng cho Docker Hub" -ForegroundColor Yellow
    docker buildx build --platform linux/amd64,linux/arm64 -t ${DOCKERHUB}/${ImageName}:${version} -t ${DOCKERHUB}/${ImageName}:${TAG} -f src/DockerfileLdapApi . --push
    
    # Kéo image về local cho sử dụng (tùy vào nền tảng hiện tại)
    docker pull ${DOCKERHUB}/${ImageName}:${version}
    docker tag ${DOCKERHUB}/${ImageName}:${version} ${ImageName}:${version}
} 
else {
    Write-Host "[$currentTime] Docker Buildx không khả dụng. Sử dụng build thông thường (chỉ hỗ trợ nền tảng hiện tại)" -ForegroundColor Yellow
    #Build new image without using cache: --no-cache
    docker build -t ${ImageName}:${version} -f src/DockerfileLdapApi .
    
    #Push Image Api to $REGISTRY_URL
    $currentTime = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Write-Host "[$currentTime] Bắt đầu đẩy api image version $version lên $REGISTRY_URL" -ForegroundColor Yellow
    docker tag ${ImageName}:${version} ${REGISTRY_URL}/${ImageName}:${version}
    docker push ${REGISTRY_URL}/${ImageName}:${version}
    
    $currentTime = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Write-Host "[$currentTime] Bắt đầu đẩy api image [$TAG] lên [$REGISTRY_URL]" -ForegroundColor Yellow
    docker tag ${ImageName}:${version} ${REGISTRY_URL}/${ImageName}:${TAG}
    docker push ${REGISTRY_URL}/${ImageName}:${TAG}
    
    #Create Tag Image to $DOCKERHUB
    $currentTime = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Write-Host "[$currentTime] Bắt đầu đổi image tag cho Docker Hub" -ForegroundColor Yellow
    docker tag ${ImageName}:${version} ${DOCKERHUB}/${ImageName}:${version}
    docker tag ${ImageName}:${version} ${DOCKERHUB}/${ImageName}:${TAG}
    
    Write-Host "[$currentTime] CẢNH BÁO: Image chỉ được build cho nền tảng hiện tại. Để hỗ trợ đa nền tảng, hãy cài đặt Docker Buildx." -ForegroundColor Red
}

$currentTime = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
Write-Host "[$currentTime] Đã build image verion: $version thành công." -ForegroundColor Green

$endTime = Get-Date
$totalTime = $endTime - $startTime
$formattedTime = "{0:hh\:mm\:ss}" -f $totalTime
Write-Host "[$currentTime] Kết thúc build Api, thời gian thực hiện: $formattedTime" -ForegroundColor Cyan