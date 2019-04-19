import sys
from PyQt5.QtWidgets import QMainWindow,QInputDialog,QWidget,QAction,QActionGroup,QLabel,QLineEdit,QCompleter,\
	QTableWidget,QTextBrowser,QSplitter,QGridLayout,QMessageBox,QTableWidgetItem,QFileDialog,QPushButton,QApplication
from PyQt5.QtGui import QIcon,QColor
from PyQt5.QtCore import Qt,QStringListModel
from scapy.all import *
from threading import Thread
from re import match
from io import BytesIO

class MainGui(QMainWindow):
	def __init__(self):
		self.sniffer=Sniffer()
		self.sniffer.interface,ok=QInputDialog.getItem(QWidget(),'Sniffer','Welcome!\n\nChoose Interface:',\
														self.sniffer.interfaces,0,False)
		if ok:
			super().__init__()
			self.initUI()
			self.reassembler=Reassembler()
		else:
			exit()

	def initUI(self):
		'''Define action'''
		self.open_act=QAction(QIcon('./icons/open.png'),'Open',self)
		self.open_act.setShortcut('Ctrl+O')
		self.open_act.triggered.connect(self.OpenFile)
		self.save_act=QAction(QIcon('./icons/save.png'),'Save',self)
		self.save_act.setShortcut('Ctrl+S')
		self.save_act.triggered.connect(self.SaveFile)
		self.save_act.setEnabled(False)
		self.quit_act=QAction(QIcon('./icons/quit.png'),'Quit',self)
		self.quit_act.setShortcut('Ctrl+Q')
		self.quit_act.triggered.connect(self.close)
		self.filter_find_act=QAction(QIcon('./icons/filter&find.png'),'Filter and Find',self)
		self.filter_find_act.setShortcut('Ctrl+F')
		self.filter_find_act.triggered.connect(self.FilterPackets)
		self.filter_find_act.setEnabled(False)
		self.reassemble_act=QAction(QIcon('./icons/reassemble.png'),'Reassemble',self)
		self.reassemble_act.setShortcut('Ctrl+Alt+R')
		self.reassemble_act.triggered.connect(self.BrowseReassembly)
		self.reassemble_act.setEnabled(False)
		self.start_act=QAction(QIcon('./icons/start.png'),'Start',self)
		self.start_act.setShortcut('Ctrl+E')
		self.start_act.triggered.connect(self.StartCapture)
		self.stop_act=QAction(QIcon('./icons/stop.png'),'Stop',self)
		self.stop_act.setShortcut('Ctrl+E')
		self.stop_act.triggered.connect(self.StopCapture)
		self.stop_act.setEnabled(False)
		self.iface_act_group=QActionGroup(self)
		self.iface_act_group.triggered.connect(self.UpdateInterface)

		self.status_label=QLabel()
		self.statusBar().addPermanentWidget(self.status_label)
		self.statusBar().showMessage('Ready to capture')

		'''Define menu'''
		menubar=self.menuBar()
		file_menu=menubar.addMenu('&File')
		analyze_menu=menubar.addMenu('&Analyze')
		interface_menu=menubar.addMenu('&Interface')
		file_menu.addAction(self.open_act)
		file_menu.addAction(self.save_act)
		file_menu.addAction(self.quit_act)
		analyze_menu.addAction(self.filter_find_act)
		analyze_menu.addAction(self.reassemble_act)

		'''Interface choose menu'''
		for iface in self.sniffer.interfaces:
			iface_act=QAction(iface,self,checkable=True)
			if iface==self.sniffer.interface:
				iface_act.setChecked(True)
			self.iface_act_group.addAction(iface_act)
			interface_menu.addAction(iface_act)

		toolbar=self.addToolBar('Toolbar')
		toolbar.setMovable(False)
		toolbar.addAction(self.start_act)
		toolbar.addAction(self.stop_act)
		toolbar.addSeparator()
		toolbar.addAction(self.open_act)
		toolbar.addAction(self.save_act)
		toolbar.addSeparator()
		toolbar.addAction(self.filter_find_act)
		toolbar.addAction(self.reassemble_act)

		'''Main region for filter and find function

		filter fields include source address and port, destination address and port, protocol, and a search field
		'''
		filter_label=QLabel('Filter:')
		source_label=QLabel('Source')
		destination_label=QLabel('Destination')
		protocol_label=QLabel('Protocol')
		find_label=QLabel('	Find:')
		self.source_edit=QLineEdit()
		self.sport_edit=QLineEdit()
		self.destination_edit=QLineEdit()
		self.dport_edit=QLineEdit()
		self.protocol_edit=QLineEdit()
		self.find_edit=QLineEdit()
		self.source_edit.setClearButtonEnabled(True)
		self.sport_edit.setClearButtonEnabled(True)
		self.destination_edit.setClearButtonEnabled(True)
		self.dport_edit.setClearButtonEnabled(True)
		self.protocol_edit.setClearButtonEnabled(True)
		self.find_edit.setClearButtonEnabled(True)

		self.protocol_completer=QCompleter()
		self.protocol_completer.setCaseSensitivity(False)
		self.protocol_edit.setCompleter(self.protocol_completer)

		self.source_edit.textChanged.connect(self.UpdateSourceFilter)
		self.sport_edit.textChanged.connect(self.UpdateSportFilter)
		self.destination_edit.textChanged.connect(self.UpdateDestinationFilter)
		self.dport_edit.textChanged.connect(self.UpdateDportFilter)
		self.protocol_edit.textChanged.connect(self.UpdateProtocolFilter)
		self.find_edit.textChanged.connect(self.UpdateFindFilter)

		'''Main region to display captured or filtered packets'''
		self.packet_table=QTableWidget()
		self.packet_table.setEditTriggers(QTableWidget.NoEditTriggers)
		self.packet_table.setSelectionBehavior(QTableWidget.SelectRows)
		self.packet_table.setSelectionMode(QTableWidget.SingleSelection)
		self.packet_table.setShowGrid(False)
		self.packet_table.setMinimumHeight(80)
		self.packet_table.itemSelectionChanged.connect(self.BrowseSelectedPacket)
		self.packet_table.verticalHeader().hide()
		self.packet_table.verticalHeader().setDefaultSectionSize(25)
		self.packet_table.setColumnCount(7)
		self.packet_table.setHorizontalHeaderLabels(['No.','Time','Source','Destination','Protocol','Length','Info'])
		self.packet_table.setColumnWidth(0,60)
		self.packet_table.setColumnWidth(1,120)
		self.packet_table.setColumnWidth(2,160)
		self.packet_table.setColumnWidth(3,160)
		self.packet_table.setColumnWidth(4,100)
		self.packet_table.setColumnWidth(5,60)
		self.packet_table.setColumnWidth(6,320)
		self.packet_table.horizontalHeader().setStretchLastSection(True)

		'''Main region to browse detailed information about packet'''
		self.details_browser=QTextBrowser()
		self.bytes_browser=QTextBrowser()
		self.details_browser.setMinimumHeight(80)
		self.bytes_browser.setMinimumHeight(80)

		horizontal_splitter=QSplitter(Qt.Horizontal)
		vertical_splitter=QSplitter(Qt.Vertical)
		horizontal_splitter.addWidget(self.details_browser)
		horizontal_splitter.addWidget(self.bytes_browser)
		vertical_splitter.addWidget(self.packet_table)
		vertical_splitter.addWidget(horizontal_splitter)
		vertical_splitter.setSizes([1,1])

		'''Design mainwindow layout'''
		grid=QGridLayout()
		grid.addWidget(filter_label,0,0,1,1)
		grid.addWidget(source_label,0,1,1,1)
		grid.addWidget(self.source_edit,0,2,1,1)
		grid.addWidget(self.sport_edit,0,3,1,1)
		grid.addWidget(destination_label,0,4,1,1)
		grid.addWidget(self.destination_edit,0,5,1,1)
		grid.addWidget(self.dport_edit,0,6,1,1)
		grid.addWidget(protocol_label,0,7,1,1)
		grid.addWidget(self.protocol_edit,0,8,1,1)
		grid.addWidget(find_label,0,9,1,1)
		grid.addWidget(self.find_edit,0,10,1,1)
		grid.addWidget(vertical_splitter,1,0,1,11)
		grid.setColumnStretch(2,3)
		grid.setColumnStretch(3,1)
		grid.setColumnStretch(5,3)
		grid.setColumnStretch(6,1)
		grid.setColumnStretch(8,3)
		grid.setColumnStretch(10,2)

		central=QWidget()
		self.setCentralWidget(central)
		central.setLayout(grid)

		self.setGeometry(100,60,1120,630)
		self.setWindowIcon(QIcon('./icons/sniffer.png'))
		self.setWindowTitle('Sniffer')
		self.show()

	def closeEvent(self,event):
		'''Override default closeEvent of MainWindow

		This is for checking before quit, also finish up jobs before quit
		'''
		reply=QMessageBox.question(self,'Quit','Are you sure?',
						QMessageBox.Yes|QMessageBox.No,QMessageBox.Yes)
		if reply==QMessageBox.Yes:
			self.sniffer.capturing=False
			self.reassembler.close()
			event.accept()
		else:
			event.ignore()

	def UpdateInterface(self,iface_act):
		'''When selection in interface_menu changes, update interface'''
		self.sniffer.interface=iface_act.text()

	def StartCapture(self):
		'''Start capturing packets'''
		if not self.sniffer.capturing:
			self.sniffer.Sniff()
			self.packet_table.setRowCount(0)
			self.statusBar().showMessage(self.sniffer.interface+': live capture in progress')
			self.status_label.clear()
			self.open_act.setEnabled(False)
			self.save_act.setEnabled(False)
			self.filter_find_act.setEnabled(False)
			self.start_act.setEnabled(False)
			self.stop_act.setEnabled(True)
			self.iface_act_group.setEnabled(False)

	def StopCapture(self):
		'''Stop capturing packets'''
		self.sniffer.StopSniffing()
		self.statusBar().showMessage('Ready to capture')
		if self.sniffer.total_number:
			self.status_label.setText('Packets: {} · Displayed: {} ({:.1%})'.format(self.sniffer.total_number,\
				len(self.sniffer.packet_filter.packet_list),len(self.sniffer.packet_filter.packet_list)/self.sniffer.total_number))
		self.open_act.setEnabled(True)
		self.save_act.setEnabled(True)
		self.filter_find_act.setEnabled(True)
		self.start_act.setEnabled(True)
		self.stop_act.setEnabled(False)
		self.iface_act_group.setEnabled(True)

	def OpenFile(self):
		'''Open a pcap file'''
		file=QFileDialog.getOpenFileName(self,'Open Packets','./','pcap(*.pcap)')[0]
		if file:
			self.packet_table.setRowCount(0)
			self.statusBar().showMessage('Loading: '+file)
			self.sniffer.OpenPackets(file)
			self.statusBar().showMessage('Ready to capture')
			if self.sniffer.total_number:
				self.status_label.setText('Packets: {} · Displayed: {} ({:.1%})'.format(self.sniffer.total_number,\
					len(self.sniffer.packet_filter.packet_list),len(self.sniffer.packet_filter.packet_list)/self.sniffer.total_number))
			self.save_act.setEnabled(True)
			self.filter_find_act.setEnabled(True)

	def SaveFile(self):
		'''Save packets as unreadable pcap or readable txt'''
		file=QFileDialog.getSaveFileName(self,'Save Packets','./','unreadable(*.pcap);;readable(*.txt)')[0]
		if file:
			self.sniffer.SavePackets(file)

	def FilterPackets(self):
		'''Filter packets and display filtered packets'''
		self.sniffer.packet_filter.FilterPackets()

		self.packet_table.setRowCount(0)
		for row_number,packet_tuple in enumerate(self.sniffer.packet_filter.packet_list):
			self.packet_table.insertRow(row_number)
			for column in range(7):
				self.packet_table.setItem(row_number,column,QTableWidgetItem(packet_tuple[column]))
				self.packet_table.item(row_number,column).setBackground(packet_tuple[7])
				self.packet_table.item(row_number,column).setForeground(packet_tuple[8])
		self.packet_table.scrollToBottom()

		if self.sniffer.total_number:
			self.status_label.setText('Packets: {} · Displayed: {} ({:.1%})'.format(self.sniffer.total_number,\
				len(self.sniffer.packet_filter.packet_list),len(self.sniffer.packet_filter.packet_list)/self.sniffer.total_number))

	'''Following functions update filter string when text in the filter and find region changes

	Also, inputs are checked if valid, and background change as a prompt
	'''
	def UpdateSourceFilter(self):
		self.sniffer.packet_filter.src_filter=self.source_edit.text()
		self.sniffer.packet_filter.src_filter_enable=\
							bool(match(self.sniffer.packet_filter.address_re,self.sniffer.packet_filter.src_filter))
		if self.sniffer.packet_filter.src_filter=='':
			self.source_edit.setStyleSheet('QLineEdit { background-color: rgb(255, 255, 255) }')
		elif self.sniffer.packet_filter.src_filter_enable:
			self.source_edit.setStyleSheet('QLineEdit { background-color: rgb(175, 255, 175) }')
		else:
			self.source_edit.setStyleSheet('QLineEdit { background-color: rgb(255, 175, 175) }')

	def UpdateSportFilter(self):
		self.sniffer.packet_filter.sport_filter=self.sport_edit.text()
		self.sniffer.packet_filter.sport_filter_enable=\
							bool(match(self.sniffer.packet_filter.port_re,self.sniffer.packet_filter.sport_filter))
		if self.sniffer.packet_filter.sport_filter=='':
			self.sport_edit.setStyleSheet('QLineEdit { background-color: rgb(255, 255, 255) }')
		elif self.sniffer.packet_filter.sport_filter_enable:
			self.sport_edit.setStyleSheet('QLineEdit { background-color: rgb(175, 255, 175) }')
		else:
			self.sport_edit.setStyleSheet('QLineEdit { background-color: rgb(255, 175, 175) }')

	def UpdateDestinationFilter(self):
		self.sniffer.packet_filter.dst_filter=self.destination_edit.text()
		self.sniffer.packet_filter.dst_filter_enable=\
							bool(match(self.sniffer.packet_filter.address_re,self.sniffer.packet_filter.dst_filter))
		if self.sniffer.packet_filter.dst_filter=='':
			self.destination_edit.setStyleSheet('QLineEdit { background-color: rgb(255, 255, 255) }')
		elif self.sniffer.packet_filter.dst_filter_enable:
			self.destination_edit.setStyleSheet('QLineEdit { background-color: rgb(175, 255, 175) }')
		else:
			self.destination_edit.setStyleSheet('QLineEdit { background-color: rgb(255, 175, 175) }')

	def UpdateDportFilter(self):
		self.sniffer.packet_filter.dport_filter=self.dport_edit.text()
		self.sniffer.packet_filter.dport_filter_enable=\
							bool(match(self.sniffer.packet_filter.port_re,self.sniffer.packet_filter.dport_filter))
		if self.sniffer.packet_filter.dport_filter=='':
			self.dport_edit.setStyleSheet('QLineEdit { background-color: rgb(255, 255, 255) }')
		elif self.sniffer.packet_filter.dport_filter_enable:
			self.dport_edit.setStyleSheet('QLineEdit { background-color: rgb(175, 255, 175) }')
		else:
			self.dport_edit.setStyleSheet('QLineEdit { background-color: rgb(255, 175, 175) }')

	def UpdateProtocolFilter(self):
		'''The completer makes protocol filter input more convinient'''
		if self.sniffer.capturing:
			protocol_set=set([packet_tuple[4] for packet_tuple in self.sniffer.packet_filter.packet_list])
			self.protocol_completer.setModel(QStringListModel(protocol_set,self.protocol_completer))
		elif not self.sniffer.packet_filter.protocol_set:
			protocol_set=set([packet_tuple[4] for packet_tuple in self.sniffer.total_packets])
			self.protocol_completer.setModel(QStringListModel(protocol_set,self.protocol_completer))
			self.sniffer.packet_filter.protocol_set=protocol_set
		else:
			protocol_set=self.sniffer.packet_filter.protocol_set
		
		self.sniffer.packet_filter.protocol_filter=self.protocol_edit.text()
		self.sniffer.packet_filter.protocol_filter_enable=self.sniffer.packet_filter.protocol_filter in protocol_set
		if self.sniffer.packet_filter.protocol_filter=='':
			self.protocol_edit.setStyleSheet('QLineEdit { background-color: rgb(255, 255, 255) }')
		elif self.sniffer.packet_filter.protocol_filter_enable:
			self.protocol_edit.setStyleSheet('QLineEdit { background-color: rgb(175, 255, 175) }')
		else:
			self.protocol_edit.setStyleSheet('QLineEdit { background-color: rgb(255, 175, 175) }')

	def UpdateFindFilter(self):
		self.sniffer.packet_filter.find_filter=self.find_edit.text()

	def BrowseReassembly(self):
		'''This is for browse TCP or IP reassembly'''
		selected=self.packet_table.selectedItems()
		packet_tuple=self.sniffer.packet_filter.packet_list[selected[0].row()]
		if self.reassembler.is_tcp_segment:
			self.reassembler.ReassembleTCP(packet_tuple)
			self.reassembler.setWindowTitle('TCP Reassembly')
			reassembly=str(len(self.reassembler.packet_numbers))+' Reassembled TCP Segments:\n#'
		else:
			self.reassembler.ReassembleIP(packet_tuple)
			self.reassembler.setWindowTitle('IP Reassembly')
			reassembly=str(len(self.reassembler.packet_numbers))+' Reassembled IP Fragments:\n#'
		reassembly+=', #'.join(self.reassembler.packet_numbers)+'\n\n'
		reassembly+=self.sniffer.hexdump(self.reassembler.reassembly)
		self.reassembler.browser.setText(reassembly)
		self.reassembler.show()

	def BrowseSelectedPacket(self):
		'''Called Upon selection in packet table changes

		Browse detailed information and hexdump about packet
		'''
		selected=self.packet_table.selectedItems()
		if selected:
			packet=self.sniffer.packet_filter.packet_list[selected[0].row()]
			self.details_browser.setText(packet[-1].show(dump=True))
			self.bytes_browser.setText(self.sniffer.hexdump(packet[-1]))
			self.reassemble_act.setEnabled(self.reassembler.isFragment(packet))
		else:
			self.details_browser.clear()
			self.bytes_browser.clear()
			self.reassemble_act.setEnabled(False)

	def UpdatePacketTable(self,packet):
		'''Called each time sniffer captures a packet

		Thus glitches do appear when too many packets captured in a short time

		The function collects necessary info about packets and display in the table
		'''
		row_number=self.packet_table.rowCount()
		if row_number:
			time=packet.time-self.sniffer.initial_time
		else:
			self.sniffer.initial_time=packet.time
			self.sniffer.sniffed_time=0
			time=0

		layer_number=2
		layer=packet.getlayer(layer_number)
		while layer and layer.name not in ('Raw','Padding'):
			layer_number+=1
			layer=packet.getlayer(layer_number)
		protocol=packet.getlayer(layer_number-1).name

		if protocol=='ARP':
			source=packet.getlayer(1).hwsrc
			destination=packet.getlayer(1).hwdst
		else:
			source=packet.getlayer(1).src
			destination=packet.getlayer(1).dst
		
		'''Further analyse protocol through ports'''
		if packet.haslayer(TCP) or packet.haslayer(UDP):
			sport,dport=packet.sport,packet.dport
			if protocol=='TCP':
				sport_string=packet[TCP].fields_desc[0].i2repr(packet,sport)
				dport_string=packet[TCP].fields_desc[1].i2repr(packet,dport)
				if sport_string!=str(sport):
					protocol=sport_string.upper()
				if dport_string!=str(dport):
					protocol=dport_string.upper()
			elif protocol=='UDP':
				sport_string=packet[UDP].fields_desc[0].i2repr(packet,sport)
				dport_string=packet[UDP].fields_desc[1].i2repr(packet,dport)
				if sport_string!=str(sport):
					protocol=sport_string.upper()
				if dport_string!=str(dport):
					protocol=dport_string.upper()
		else:
			sport,dport=None,None

		info_list=packet.summary().split(' / ')[1:]
		info_list.sort(key=lambda x:len(x))

		'''The coloring rules are the default ones in Wireshark'''
		if protocol=='ARP':
			background,foreground=QColor(250,240,215),QColor(18,39,46) #ARP
		elif 'ICMP' in protocol:
			if protocol=='ICMP' and packet[ICMP].type in (3,4,5,11):
				background,foreground=QColor(18,39,46),QColor(183,247,116) #ICMP errors
			else:
				background,foreground=QColor(252,224,255),QColor(18,39,46) #ICMP or ICMPv6
		elif packet.haslayer(TCP):
			flag=int(packet[TCP].flags)
			if flag>>2&1:
				background,foreground=QColor(164,0,0),QColor(255,252,156) #TCP reset
			elif sport==80 or dport==80:
				background,foreground=QColor(228,255,199),QColor(18,39,46) #HTTP
			elif flag&3:
				background,foreground=QColor(160,160,160),QColor(18,39,46) #TCP SYN/FIN
			else:
				background,foreground=QColor(231,230,255),QColor(18,39,46) #TCP
		elif packet.haslayer(UDP):
			background,foreground=QColor(218,238,255),QColor(18,39,46) #UDP
		else:
			background,foreground=QColor(255,255,255),QColor(18,39,46)

		'''('No.','Time','Source','Destination','Protocol','Length','Info',background,foreground,sport,dport,packet)'''
		packet_tuple=(str(row_number),'{:.6f}'.format(time),source,destination,\
					protocol,str(len(packet)),info_list[-1],background,foreground,\
					sport,dport,packet)
		self.sniffer.packet_filter.packet_list.append(packet_tuple)

		self.packet_table.insertRow(row_number)
		for column in range(7):
			self.packet_table.setItem(row_number,column,QTableWidgetItem(packet_tuple[column]))
			self.packet_table.item(row_number,column).setBackground(background)
			self.packet_table.item(row_number,column).setForeground(foreground)

		'''Avoid scrolling too fast'''
		if time>0.05+self.sniffer.sniffed_time:
			self.packet_table.scrollToBottom()
			self.sniffer.sniffed_time=time

class Sniffer(object):
	def __init__(self):
		self.capturing=False
		self.packet_filter=PacketFilter()
		self.total_packets=[]
		self.total_number=0
		self.initial_time=0
		self.sniffed_time=0
		if sys.platform=='win32':
			self.interfaces=[vars(network_interface)['name'] for network_interface in vars(IFACES)['data'].values()]
		else:
			self.interfaces=get_if_list()
		self.interface=''

	def Sniff(self):
		'''Main sniff function

		Start a daemon thread for sniffing
		'''
		self.capturing=True
		self.packet_filter.packet_list=[]
		self.packet_filter.protocol_set=set()
		Thread(target=self.sniff_,daemon=True).start()

	def sniff_(self):
		'''So packets are stored in tuples, not here

		Plus a sniffing thread terminates on the change of capturing flag
		'''
		sniff(store=False,prn=gui.UpdatePacketTable,stop_filter=lambda packet:not self.capturing,iface=self.interface)

	def StopSniffing(self):
		'''Stop Capturing'''
		self.capturing=False
		self.total_packets=self.packet_filter.packet_list
		self.total_number=len(self.total_packets)

	def OpenPackets(self,filename):
		'''Open packets, actually works like a quick start and stop'''
		self.packet_filter.packet_list=[]
		self.packet_filter.protocol_set=set()
		sniff(store=False,offline=filename,prn=gui.UpdatePacketTable)
		self.total_packets=self.packet_filter.packet_list
		self.total_number=len(self.total_packets)

	def SavePackets(self,filename):
		'''Save displayed packets for further use'''
		packets=[packet_tuple[-1] for packet_tuple in self.packet_filter.packet_list]
		if filename.endswith('pcap'):
			wrpcap(filename,packets)
		elif filename.endswith('txt'):
			with open(filename,'w') as f:
				for index,packet in enumerate(packets):
					f.write('No. '+str(index)+':\n'+packet.show(dump=True)+'\n')
		else:
			pass

	def hexdump(self,x):
		'''This is actually a function in scapy

		However, implementation in current version of scapy (v2.4.0) does have mistakes

		Thus, I modified the implementation a little
		'''
		s=""
		x=raw(x)
		x_len=len(x)
		i=0
		while i<x_len:
			s+="%04x  " %i
			for j in range(16):
				if j==8:
					s+=" "
				if i+j<x_len:
					s+="%02X " %orb(x[i+j])
				else:
					s+="   "
			s+=" %s\n"%sane_color(x[i:i+16])
			i+=16
		s=s[:-1] if s.endswith("\n") else s
		return s

class PacketFilter(object):
	def __init__(self):
		self.packet_list=[]
		self.src_filter_enable=False
		self.sport_filter_enable=False
		self.dst_filter_enable=False
		self.dport_filter_enable=False
		self.protocol_filter_enable=False
		self.src_filter=''
		self.sport_filter=''
		self.dst_filter=''
		self.dport_filter=''
		self.protocol_filter=''
		self.find_filter=''
		self.protocol_set=set()
		
		'''Checking input validation through regex'''
		self.address_re=(r'^((25[0-5]|(2[0-4]|1\d|[1-9])?\d)\.){3}(25[0-5]|(2[0-4]|1\d|[1-9])?\d)$|'
						#IPv4 regex
						r'^((::)|'
						r'((([1-9a-f][0-9a-f]{0,3}|0):){1,7}:)|'
						r'((([1-9a-f][0-9a-f]{0,3}|0):){1,6}:([1-9a-f][0-9a-f]{0,3}|0))|'
						r'((([1-9a-f][0-9a-f]{0,3}|0):){1,5}(:([1-9a-f][0-9a-f]{0,3}|0)){1,2})|'
						r'((([1-9a-f][0-9a-f]{0,3}|0):){1,4}(:([1-9a-f][0-9a-f]{0,3}|0)){1,3})|'
						r'((([1-9a-f][0-9a-f]{0,3}|0):){1,3}(:([1-9a-f][0-9a-f]{0,3}|0)){1,4})|'
						r'((([1-9a-f][0-9a-f]{0,3}|0):){1,2}(:([1-9a-f][0-9a-f]{0,3}|0)){1,5})|'
						r'(([1-9a-f][0-9a-f]{0,3}|0):(:([1-9a-f][0-9a-f]{0,3}|0)){1,6})|'
						r'(:(:([1-9a-f][0-9a-f]{0,3}|0)){1,7})|'
						r'((([1-9a-f][0-9a-f]{0,3}|0):){7}([1-9a-f][0-9a-f]{0,3}|0)))$')
						#IPv6 regex
		self.port_re=r'^([1-9]\d{0,3}|[1-5]\d{4}|6[0-4]\d{3}|65[0-4]\d{2}|655[0-2]\d|6553[0-5])$' #port regex

	def FilterPackets(self):
		'''Filter fields which is checked valid'''
		self.packet_list=gui.sniffer.total_packets
		if self.src_filter_enable:
			filter_rule=lambda packet_tuple:self.src_filter==packet_tuple[2]
			self.packet_list=filter(filter_rule,self.packet_list)
		if self.sport_filter_enable:
			filter_rule=lambda packet_tuple:self.sport_filter==str(packet_tuple[-3])
			self.packet_list=filter(filter_rule,self.packet_list)
		if self.dst_filter_enable:
			filter_rule=lambda packet_tuple:self.dst_filter==packet_tuple[3]
			self.packet_list=filter(filter_rule,self.packet_list)
		if self.dport_filter_enable:
			filter_rule=lambda packet_tuple:self.dport_filter==str(packet_tuple[-2])
			self.packet_list=filter(filter_rule,self.packet_list)
		if self.protocol_filter_enable:
			filter_rule=lambda packet_tuple:self.protocol_filter==packet_tuple[4]
			self.packet_list=filter(filter_rule,self.packet_list)
		filter_rule=lambda packet_tuple:bytes(self.find_filter,encoding='UTF-8') in raw(packet_tuple[-1])
		self.packet_list=list(filter(filter_rule,self.packet_list))

class Reassembler(QWidget):
	def __init__(self):
		super().__init__()
		self.initUI()
		self.packet_numbers=[]
		self.IP_fragments=[]
		self.TCP_segments=[]
		self.reassembly=bytes()

	def initUI(self):
		self.browser=QTextBrowser()
		save_button=QPushButton('Save Reassembly',self)
		save_button.clicked.connect(self.SaveReassembly)

		grid=QGridLayout()
		grid.addWidget(self.browser,0,0,1,2)
		grid.addWidget(save_button,1,0,1,1)
		self.setLayout(grid)

		self.setGeometry(300,100,500,500)
		self.setWindowIcon(QIcon('./icons/reassemble.png'))

	def isFragment(self,packet):
		'''Check if packet is IP fragment or TCP segment and decide whether it can be reassembled'''
		frag=False
		self.is_tcp_segment=False
		if packet[-1].haslayer(IP):
			if packet[-1][IP].frag and packet[-1][IP].flags!=1:
				filter_rule=lambda packet_tuple:packet[2:4]==packet_tuple[2:4] and packet_tuple[-1].haslayer(IP)\
											and packet[-1][IP].id==packet_tuple[-1][IP].id
				self.packet_numbers=[packet_tuple[0] for packet_tuple in filter(filter_rule,gui.sniffer.total_packets)]
				self.IP_fragments=[packet_tuple[-1] for packet_tuple in filter(filter_rule,gui.sniffer.total_packets)]
				frag=frag or len(self.IP_fragments)>1

			if packet[-1].haslayer(TCP):
				if int(packet[-1][TCP].flags)&1:
					filter_rule=lambda packet_tuple:packet[2:4]==packet_tuple[2:4] and packet_tuple[-1].haslayer(TCP)\
												and packet[-1][TCP].ack==packet_tuple[-1][TCP].ack\
												and packet_tuple[-1][IP].len>packet_tuple[-1][TCP].dataofs*8
					self.packet_numbers=[packet_tuple[0] for packet_tuple in filter(filter_rule,gui.sniffer.total_packets)]
					self.TCP_segments=[packet_tuple[-1] for packet_tuple in filter(filter_rule,gui.sniffer.total_packets)]
					self.is_tcp_segment=len(self.TCP_segments)>1
					frag=frag or self.is_tcp_segment
		return frag

	def ReassembleTCP(self,packet):
		'''Reassemble TCP segments'''
		return_buffer=BytesIO()
		packet_list=sorted(self.TCP_segments,key=lambda packet:packet[TCP].seq)
		first=packet_list[0][TCP].seq
		for packet in packet_list:
			return_buffer.seek(packet[TCP].seq-first)
			return_buffer.write(raw(packet[TCP].payload))
		self.reassembly=return_buffer.getvalue()

	def ReassembleIP(self,packet):
		'''Reassemble IP fragments'''
		return_buffer=BytesIO()
		for packet in sorted(self.IP_fragments,key=lambda packet:packet[IP].frag)[::-1]:
			return_buffer.seek(packet[IP].frag*8)
			return_buffer.write(raw(packet[IP].payload))
		self.reassembly=return_buffer.getvalue()

	def SaveReassembly(self):
		'''Save reassembly result as binary file'''
		file=QFileDialog.getSaveFileName(self,'Save Reassembly','./','')[0]
		if file:
			with open(file,'wb') as f:
				f.write(self.reassembly)

if __name__=='__main__':
	app=QApplication(sys.argv)
	gui=MainGui()
	sys.exit(app.exec_())
