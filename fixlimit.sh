#!/bin/bash

# Set repo URL
REPO2="https://raw.githubusercontent.com/Andyyuda/vip/main/"

# Hapus file lama jika ada
rm -f /usr/bin/limit-ip
rm -f /root/limit.sh

# Mengunduh dan mengatur limit.sh
wget ${REPO2}limit/limit.sh -O /root/limit.sh
chmod +x /root/limit.sh
/root/limit.sh

# Mengatur limit-ip
wget -q -O /usr/bin/limit-ip "${REPO2}limit/limit-ip"
chmod +x /usr/bin/limit-ip
sed -i 's/\r//' /usr/bin/limit-ip

# Konfigurasi dan memulai layanan vmip
cat > /etc/systemd/system/vmip.service << EOF
[Unit]
Description=My vmip service
After=network.target

[Service]
WorkingDirectory=/root
ExecStart=/usr/bin/limit-ip vmip
Restart=always

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl restart vmip
systemctl enable vmip

# Konfigurasi dan memulai layanan vlip
cat > /etc/systemd/system/vlip.service << EOF
[Unit]
Description=My vlip service
After=network.target

[Service]
WorkingDirectory=/root
ExecStart=/usr/bin/limit-ip vlip
Restart=always

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl restart vlip
systemctl enable vlip

# Konfigurasi dan memulai layanan trip
cat > /etc/systemd/system/trip.service << EOF
[Unit]
Description=My trip service
After=network.target

[Service]
WorkingDirectory=/root
ExecStart=/usr/bin/limit-ip trip
Restart=always

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl restart trip
systemctl enable trip

echo "Semua layanan berhasil dikonfigurasi dan dijalankan."
