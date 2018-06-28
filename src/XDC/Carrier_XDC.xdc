#########################################################################################################
#########################################################################################################
# Zynq-7000 based Implementation of the KHAZAD Block Cipher
# Yossef Shitzer & Efraim Wasserman
# Jerusalem College of Technology - Lev Academic Center (JCT)
# Department of electrical and electronic engineering
# 2018
#########################################################################################################
#########################################################################################################
# This is an XDC file for the outputs going to the MicroZed I/O Carrier Card.
#########################################################################################################
#########################################################################################################
# Version 2.0: ECB+CBC implementation
#########################################################################################################
#########################################################################################################
# user LED 0:
set_property -dict {PACKAGE_PIN U14 IOSTANDARD LVCMOS33} [get_ports RST_LED]
# user LED 1:
set_property -dict {PACKAGE_PIN U15 IOSTANDARD LVCMOS33} [get_ports PL_ready_LED]
# user LED 3:
set_property -dict {PACKAGE_PIN U19 IOSTANDARD LVCMOS33} [get_ports encryption_LED]
# user LED 4:
set_property -dict {PACKAGE_PIN R19 IOSTANDARD LVCMOS33} [get_ports decryption_LED]
# user LED 6:
set_property -dict {PACKAGE_PIN P14 IOSTANDARD LVCMOS33} [get_ports ECB_LED]
# user LED 7:
set_property -dict {PACKAGE_PIN R14 IOSTANDARD LVCMOS33} [get_ports CBC_LED]