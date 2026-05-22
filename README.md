# MÔ PHỎNG TẤN CÔNG DOS/DDOS VÀ GIẢI PHÁP GIẢM THIỂU

Dự án nghiên cứu, mô phỏng các cuộc tấn công DoS/DDoS và triển khai các biện pháp tường lửa nhằm phòng chống, giảm thiểu thiệt hại cho hệ thống Web Server.

## 🛠 Công Cụ & Môi Trường
* **Môi trường mô phỏng:** Hệ điều hành Kali Linux chạy trên máy ảo (VMware).
* **Công cụ tấn công:** Công cụ mã nguồn mở `k6` (dùng JavaScript) để tạo luồng request HTTP/HTTPS cường độ cao. Kết hợp với **Docker** để tạo nhiều container giả lập mạng lưới botnet tấn công phân tán (DDoS).
* **Giải pháp phòng thủ:** Tường lửa (Firewall) tự code kết hợp cùng dịch vụ bảo mật hạ tầng Cloudflare.

## 🔗 Liên Kết Truy Cập Hệ Thống

* 🌐 **[Truy cập Web Server (Mục tiêu thử nghiệm)] https://spiritads.onrender.com/**: Ứng dụng web được thiết lập trên môi trường Internet để kiểm thử khả năng chịu tải thực tế.
* 📊 **[Truy cập Dashboard Giám Sát (Cổng 3000)]https://spiritads.onrender.com/monitor?key=Phuc2026secret**: Hệ thống giao diện trực quan giúp theo dõi thời gian thực các chỉ số quan trọng như: tổng lượng requests, requests/giây (RPS), danh sách IP đang truy cập và log phân tích chuyên sâu.

## 🚀 Kịch Bản & Kết Quả Thực Nghiệm

### 1. Mô Phỏng Tấn Công DoS (Một Nguồn)
* **Cách thức:** Dùng `k6` trên 1 máy Kali Linux đẩy liên tục số lượng lớn request đến Web Server.
* **Kết quả:** * Khi lưu lượng đạt 3000 requests, web bắt đầu giật lag, phản hồi chậm. 
  * Khi chạm ngưỡng 4000 requests từ cùng 1 địa chỉ IP, máy chủ quá tải, mất kết nối hoàn toàn và trang web bị sập.

### 2. Mô Phỏng Tấn Công DDoS (Đa Nguồn)
* **Cách thức:** Triển khai 10 Docker container chạy `k6` song song để giả lập nhiều máy bot tấn công đồng loạt.
* **Kết quả:** Vì lượng request ập đến từ nhiều IP thay đổi liên tục, máy chủ không kịp phản hồi và trang web sập ngay lập tức chỉ trong vài giây, mức độ tàn phá nhanh và nguy hiểm hơn hẳn DoS.

### 3. Giải Pháp Giảm Thiểu (Phòng Thủ)
* **Firewall nội bộ:** Phát hiện các hành vi gửi request bất thường, giới hạn tốc độ truy cập (Rate Limiting) và có khả năng chặn (ban) vĩnh viễn các địa chỉ IP độc hại.
* **Cloudflare:** Đóng vai trò là lớp khiên bên ngoài giúp ẩn IP gốc, phân tán lưu lượng truy cập khổng lồ, hỗ trợ bộ nhớ đệm (caching) và CDN để duy trì tốc độ truy cập.
* **Kết quả:** Hệ thống bảo mật nhiều tầng (multi-layer) này giúp chủ động lọc lưu lượng độc hại, giảm tải cho máy chủ và đảm bảo người dùng hợp lệ vẫn có thể truy cập hệ thống an toàn.

## 📝 Tổng Kết
Dự án không chỉ mô phỏng thành công cơ chế phá hoại của các cuộc tấn công từ chối dịch vụ mà còn xây dựng được kiến trúc bảo vệ kết hợp giữa giải pháp Firewall linh hoạt nội bộ và sức mạnh hạ tầng đám mây. Tuy việc tự code Firewall vẫn bị giới hạn bởi tài nguyên phần cứng, nhưng đây là nền tảng vững chắc để phát triển các hệ thống giám sát tự động hóa, tích hợp AI trong tương lai.
