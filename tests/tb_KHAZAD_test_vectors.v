`timescale 1 ns / 1 ps
/********************************************************************************************************
*********************************************************************************************************
Zynq-7000 based Implementation of the KHAZAD Block Cipher
Yossef Shitzer & Efraim Wasserman
Jerusalem College of Technology - Lev Academic Center (JCT)
Department of electrical and electronic engineering
2018
*********************************************************************************************************
*********************************************************************************************************
This module is a test bench for KHAZAD.v source code simulation.
Each line in the file "KHAZAD_test_vectors_simple.txt" contains plaintext, key and ciphertext.
The design follows this file, 
and for each line performs encryption (and checks the result), decryption (and checks the result), then proceeds to the next line.
*********************************************************************************************************
*********************************************************************************************************/
module tb_KHAZAD_test_vectors();

integer      data_file_in, statusD;
reg  [63:0]  plaintext, ciphertext;
reg  [127:0] key;
reg  [31:0]  report_string;  // no real string type in verilog
reg          tb_CLK  = 0, tb_RST = 1, tb_enc = 1, tb_start = 0;
wire [79:0]  mode_string;
wire [63:0]  tb_data_in, tb_data_out;
wire		 tb_last_round, tb_only_data;

assign tb_only_data = 0;
assign mode_string = (tb_enc == 1) ? "Encryption" : "Decryption";
assign tb_data_in  = (tb_enc == 1) ? plaintext : ciphertext;

always
  #10 tb_CLK = ~tb_CLK;

initial
  data_file_in = $fopen("KHAZAD_test_vectors_simple.txt","r");

initial
begin
  repeat (10) @ (posedge tb_CLK);
  #17 tb_RST <= 0;
  statusD <= $fscanf(data_file_in, "%h %h %h\n", key, plaintext, ciphertext);
  tb_start <= 1;
  while (!$feof(data_file_in))
  begin
	if (tb_last_round)
	  begin
	    @ (posedge tb_CLK);  // wait another clock for last round to end
	    if ((tb_enc == 1 && tb_data_out == ciphertext) || (tb_enc == 0 && tb_data_out == plaintext))
	      report_string = "PASS";
	    else
		  begin
	        report_string = "FAIL";
			$error;
		  end
		$display("time = %8t | %s | K = %016h | P = %016h | C = %016h | Result = %016h | %s",
				 $time, mode_string, key, plaintext, ciphertext, tb_data_out, report_string);
	    if (tb_enc == 0)  // if decryption was also tested, read the next line
		  statusD <= $fscanf(data_file_in, "%h %h %h\n", key, plaintext, ciphertext);
		tb_enc = ~tb_enc;
		tb_start <= 1;
	  end
	else
	  begin
	    @ (posedge tb_CLK);
	    tb_start <= 0;
	  end
  end
  $finish;
end

KHAZAD DUT
(
.data_in (tb_data_in),
.key_in (key),
.CLK (tb_CLK),
.RST (tb_RST),
.enc (tb_enc),
.start (tb_start),
.only_data (tb_only_data),
.data_out (tb_data_out),
.last_round (tb_last_round)
);

endmodule