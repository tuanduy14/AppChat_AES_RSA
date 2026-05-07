"# AppChat_AES_RSA" 

Chạy server:

python server/server.py

Chạy attacker (MITM):

python attacker/attacker.py

Chạy client Alice và Bob qua MITM:

python client/client.py alice mitm

python client/client.py bob mitm

Khi attacker intercept tin nhắn, bạn có thể nhập nội dung mới, ENTER hoặc /skip để giữ nguyên, /drop để bỏ qua. Nếu nội dung không thay đổi, attacker tạo signature hợp lệ, client không alert. Nếu nội dung bị thay đổi, attacker không forward signature, client alert integrity violation và hiển thị [POTENTIALLY MODIFIED] mà không ngắt kết nối.







