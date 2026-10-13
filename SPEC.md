# Specification: WebRecon Dashboard Modernization & Visual Intelligence

## 1. Mục tiêu (Objectives)
Nâng cấp giao diện người dùng của **WebRecon Dashboard** (`src/webrecon/api/static/index.html`) từ phong cách tối giản/phẳng sang giao diện trạm làm việc (Workstation) hiện đại, cao cấp theo phong cách Linear / Vercel / Raycast. Giữ nguyên tính chất tự chứa (self-contained, không cần build step, tương thích 100% các API hiện có và hỗ trợ song ngữ EN/VI).

---

## 2. Các thành phần nâng cấp chi tiết (Component Breakdown)

### 2.1. Typography & Hệ thống Design Tokens (Aesthetics & Depth)
- **Fonts**: Nhúng Google Fonts (`Plus Jakarta Sans` cho UI, `JetBrains Mono` cho URI/code/hashes) với fallback mượt mà về system font khi offline.
- **Glassmorphism & Lighting**: 
  - Nền Deep Slate Navy (`#080b11`), panel viền kính mờ (`rgba(255, 255, 255, 0.08)`), ánh sáng gradient ambient.
  - Card elevation với bóng mờ (`box-shadow: 0 12px 32px rgba(0, 0, 0, 0.45)`).
  - Hover micro-animations trên button, hàng bảng (table rows) và thẻ tương tác.

### 2.2. Interactive Auth Flow Pipeline (Trực quan hóa luồng xác thực)
- Thay thế danh sách bước thô (`<ol class="steps">`) bằng **Sơ đồ luồng tương tác (Visual Flow Pipeline)**:
  - Các bước được hiển thị dưới dạng chuỗi Pipeline trực quan (Responsive Flow Node Cards) nối với nhau bằng mũi tên chuyển trạng thái có hiệu ứng hoạt họa (animated connectors).
  - Mỗi node biểu diễn:
    - Icon trực quan: `🌐 Form đăng nhập`, `🔑 Endpoint nhận auth`, `🍪 Cookie phiên làm việc`, `👤 User Identity / Profile`.
    - HTTP Method badge nổi bật (POST cam, GET xanh cyan).
    - Trạng thái quan sát (observed với pulsing green dot, referenced với subtle pill).
- Bổ sung bảng Role Badges màu sắc chuyên biệt: `login` (blue), `logout` (rose), `reset` (amber), `identity` (violet), `token` (cyan).

### 2.3. HTTP Method Badges chuẩn OpenAPI / Postman
- Chuẩn hóa hiển thị HTTP Method trên toàn bộ Dashboard (Endpoints view, Auth Flow, Timeline, Attack Surface):
  - `GET`: Cyan/Teal background (`#0e7490`)
  - `POST`: Amber/Orange background (`#b45309`)
  - `PUT`: Purple background (`#6d28d9`)
  - `DELETE`: Rose/Red background (`#be123c`)
  - `PATCH`: Emerald background (`#047857`)
- Nút bấm 1-click Copy URI kèm tooltip phản hồi tức thì ("Đã chép!").

### 2.4. Custom Scan Quick-Switcher (Thay thế thẻ `<select>` mặc định)
- Thay thế dropdown native HTML `<select id="scanSelect">` bằng **Custom Quick Switcher Popover**:
  - Nút bấm trigger hiển thị target hiện tại, favicon, badge trạng thái (`success` xanh, `findings` đỏ) và phím tắt `Ctrl + K`.
  - Hộp tìm kiếm popover có ô search lọc nhanh domain/URL.
  - Danh sách scan dạng cards phân chia rõ ràng: URL mục tiêu, số lượng lỗ hổng/phát hiện, thời gian thực hiện dạng tương đối ("vừa xong", "2 giờ trước").

### 2.5. Nâng cấp Thẻ KPI & Gauge đo độ tin cậy
- Thêm icon nhận diện cho từng chỉ số (Risk, Findings, Endpoints, JS Files, AI Status).
- Thêm vòng đo phần trăm (Confidence Meter) trực quan trên các card tỷ lệ.

---

## 3. Tệp tin sửa đổi (Files to be modified)
- `src/webrecon/api/static/index.html`: Cập nhật CSS tokens, component styles và các hàm render (`authFlowView`, `selectScan` switcher, method badges, v.v.).

---

## 4. Kế hoạch xác minh & kiểm thử (Verification Steps)
1. **Kiểm tra cú pháp JS**: Chạy `node --check` hoặc kiểm tra syntax đảm bảo không có lỗi biên dịch JavaScript.
2. **Kiểm tra hiển thị trình duyệt**:
   - Truy cập `http://localhost:8000/#/auth-flow` xác nhận pipeline hiển thị đẹp, rõ ràng, có mũi tên nối và badges.
   - Thử nghiệm Quick Switcher tìm kiếm và chuyển đổi giữa các lượt scan (`gnddt.com`, `stealx.fr`).
   - Kiểm tra giao diện ở cả Dark Mode và Light Mode.
   - Kiểm tra song ngữ EN và VI không bị vỡ giao diện.
3. **Kiểm thử hồi quy (Regression Test)**: Chạy `rtk .venv\Scripts\pytest -q` kiểm tra API backend và test suite không bị ảnh hưởng.
