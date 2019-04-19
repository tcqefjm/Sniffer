项目二：网络嗅探器（已实现全部功能）

运行平台：
	Windows/Linux
	(理论上Mac OS正确配置环境后也可，但未经测试)

依赖：
	1. Python 3
	2. PyQt5 (最新版本v5.11.3)
		pip install PyQt5
	3. scapy (最新版本v2.4.0)
		pip install scapy
	4. 嗅探库
		Windows平台: npcap (最新版本v0.99-r8)
			下载 https://nmap.org/npcap/dist/npcap-0.99-r8.exe 并运行
		Ubuntu/Debian平台： tcpdump (最新版本v4.9.2)
			sudo apt-get install tcpdump
		其他平台: 请参考 https://scapy.readthedocs.io/en/latest/installation.html#platform-specific-instructions

测试方法：
	无需编译，进入该目录后运行命令
		python sniffer.py