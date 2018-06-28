/********************************************************************************************************
*********************************************************************************************************
Zynq-7000 based Implementation of the KHAZAD Block Cipher
Yossef Shitzer & Efraim Wasserman
Jerusalem College of Technology - Lev Academic Center (JCT)
Department of electrical and electronic engineering
2018
*********************************************************************************************************
*********************************************************************************************************
For CBC encryption, XOR is made with the last cipher output, so d_out_KHAZAD is used.
But for CBC decryption XOR is made with previous cipher input, not the current cipher input, so the previous cipher 
needs to be saved in memory. We named it Cminus1[63:0].
The current cipher input may be needed for future XOR. In case this input will not remain valid in the input ports, 
we save it too as C[63:0].
*********************************************************************************************************
*********************************************************************************************************/
module CBC_dec_memory
(
  input				CLK		,
  input 			RST		,
  input 			start	,
  input  	 [63:0] C		,
  output reg [63:0] Cminus1
);

reg [63:0] mem_buffer;

always @(posedge CLK)
begin
	if (RST)
		begin
			Cminus1 <= 64'h0;
			mem_buffer <= 64'h0;
		end
	else
		if (start) // for each start pulse, advance the saved ciphers
			begin
				mem_buffer <= C;
				Cminus1 <= mem_buffer;
			end
end

endmodule