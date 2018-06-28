/********************************************************************************************************
*********************************************************************************************************
Zynq-7000 based Implementation of the KHAZAD Block Cipher
Yossef Shitzer & Efraim Wasserman
Jerusalem College of Technology - Lev Academic Center (JCT)
Department of electrical and electronic engineering
2018
*********************************************************************************************************
*********************************************************************************************************
This module implements the complete KHAZAD algorithm, using only the round_function_plus module and a finite-state machine (FSM).
A full operation takes 24 clock-cycles: 9 cycles to calculate nine 64-bit round keys, 7 cycles to calculate seven 64-bit inverse decryption keys, 
and 8 cycles to perform 8-rounds encryption/decryption.
*********************************************************************************************************
*********************************************************************************************************
Inputs & outputs description:
Input data_in: 64-bit data, plaintext (for encryption) or ciphertext (for decryption).
Input key_in: 128-bit secret key.
Input CLK: clock pulses.
Input RST: design reset signal.
Input enc: the desired operation. enc = 1: encryption, enc = 0: decryption.
Input start: start operation signal. start = 1: begin operation, start = 0: on idle.
Input only_data: indicates the key period. only_data = 1: new data_in, same key. only_data = 0: new data_in and new key_in, need to recalculate round keys.
Output data_out: 64-bit data, ciphertext (for encryption) or plaintext (for decryption).
Output last_round: 1-clock-cycle-width pulse indicates the last round is being calculated. When the flag turns on, last round has begun. When the flag 
turns off, last round has ended, and data_out is valid.
*********************************************************************************************************
*********************************************************************************************************
The KHAZAD algorithm is described in: 
P. Barreto and V. Rijmen, The Khazad Legacy-Level Block Cipher
available at: 
https://www.cosic.esat.kuleuven.be/nessie/tweaks.html
*********************************************************************************************************
*********************************************************************************************************/
module KHAZAD
(
  input  [63:0] data_in,
  input  [127:0] key_in,
  input  CLK, RST, enc, start, only_data,
  output reg [63:0] data_out,
  output reg last_round
);

reg [4: 0] ctrl;  // controls the state of the FSM
reg [63:0] round_keys [0:8];
reg [63:0] inv_round_keys [1:7];
reg [63:0] Kminus2, input_1, input_2; // inputs for round_function_plus
reg only_theta_req;
wire [63:0] only_theta_out, last_round_out, rho_out;

round_function_plus R (input_1, input_2, only_theta_req, only_theta_out, last_round_out, rho_out);

always @(posedge CLK)
begin

  if (RST)
	begin
		ctrl <= 5'd0;
		data_out <= 64'h0;
		only_theta_req <= 0;
		last_round <= 0;
	end

  else
	  case (ctrl)

		5'd0:
			begin
				if (last_round)				   		// FSM got here after last round was completed
					data_out <= last_round_out;  	// output data_out only when it's valid
				last_round <= 0;			   		// turn off the flag
				if (start)
					if (only_data)			   		// no need for key schedule. start encryption/decryption operation to save time
						begin
							if (enc)		        // encryption
								begin
									input_1 <= data_in ^ round_keys[0];
									input_2 <= round_keys[1];
								end
							else				    // decryption
								begin
									input_1 <= data_in ^ round_keys[8];
									input_2 <= inv_round_keys[7];
								end
							ctrl <= 5'd17;
						end
					else							// key schedule needed. start calculating the round keys
						begin
							Kminus2 <= key_in[127:64];
							input_1 <= key_in[63:0];
							input_2 <= 64'hba542f7453d3d24d;  // round constant
							ctrl <= 5'd1;
						end
				else
					ctrl <= 5'd0;  					// if start==0, do nothing, stay in this state and wait for start signal
			end

		5'd1:	// key schedule continuation
			begin
				round_keys[0] <= rho_out ^ Kminus2;
				Kminus2 <= input_1;
				input_1 <= rho_out ^ Kminus2;
				input_2 <= 64'h50ac8dbf70529a4c;
				ctrl <= 5'd2;
			end

		5'd2:
			begin
				round_keys[1] <= rho_out ^ Kminus2;
				Kminus2 <= input_1;
				input_1 <= rho_out ^ Kminus2;
				input_2 <= 64'head597d133515ba6;
				ctrl <= 5'd3;
			end

		5'd3:
			begin
				round_keys[2] <= rho_out ^ Kminus2;
				Kminus2 <= input_1;
				input_1 <= rho_out ^ Kminus2;
				input_2 <= 64'hde48a899db32b7fc;
				ctrl <= 5'd4;
			end

		5'd4:
			begin
				round_keys[3] <= rho_out ^ Kminus2;
				Kminus2 <= input_1;
				input_1 <= rho_out ^ Kminus2;
				input_2 <= 64'he39e919be2bb416e;
				ctrl <= 5'd5;
			end

		5'd5:
			begin
				round_keys[4] <= rho_out ^ Kminus2;
				Kminus2 <= input_1;
				input_1 <= rho_out ^ Kminus2;
				input_2 <= 64'ha5cb6b95a1f3b102;
				ctrl <= 5'd6;
			end

		5'd6:
			begin
				round_keys[5] <= rho_out ^ Kminus2;
				Kminus2 <= input_1;
				input_1 <= rho_out ^ Kminus2;
				input_2 <= 64'hccc41d14c363da5d;
				ctrl <= 5'd7;
			end

		5'd7:
			begin
				round_keys[6] <= rho_out ^ Kminus2;
				Kminus2 <= input_1;
				input_1 <= rho_out ^ Kminus2;
				input_2 <= 64'h5fdc7dcd7f5a6c5c;
				ctrl <= 5'd8;
			end

		5'd8:
			begin
				round_keys[7] <= rho_out ^ Kminus2;
				Kminus2 <= input_1;
				input_1 <= rho_out ^ Kminus2;
				input_2 <= 64'hf726ffede89d6f8e;
				ctrl <= 5'd9;
			end

		5'd9:	// key schedule: end of calculating the round keys, start calculating the inverse decryption keys
			begin
				round_keys[8] <= rho_out ^ Kminus2;
				only_theta_req <= 1;
				input_1 <= round_keys[1];
				ctrl <= 5'd10;
			end

		5'd10:
			begin
				inv_round_keys[1] <= only_theta_out;
				input_1 <= round_keys[2];
				ctrl <= 5'd11;
			end

		5'd11:
			begin
				inv_round_keys[2] <= only_theta_out;
				input_1 <= round_keys[3];
				ctrl <= 5'd12;
			end

		5'd12:
			begin
				inv_round_keys[3] <= only_theta_out;
				input_1 <= round_keys[4];
				ctrl <= 5'd13;
			end

		5'd13:
			begin
				inv_round_keys[4] <= only_theta_out;
				input_1 <= round_keys[5];
				ctrl <= 5'd14;
			end

		5'd14:
			begin
				inv_round_keys[5] <= only_theta_out;
				input_1 <= round_keys[6];
				ctrl <= 5'd15;
			end

		5'd15:
			begin
				inv_round_keys[6] <= only_theta_out;
				input_1 <= round_keys[7];
				ctrl <= 5'd16;
			end

		5'd16:	// end of calculating the inverse keys, end of key schedule, start encryption/decryption
			begin
				inv_round_keys[7] <= only_theta_out;
				only_theta_req <= 0;
				if (enc)
				  begin
				    input_1 <= data_in ^ round_keys[0];
				    input_2 <= round_keys[1];
				  end	
				else
				  begin
				    input_1 <= data_in ^ round_keys[8];
				    input_2 <= only_theta_out;
				  end	
				ctrl <= 5'd17;
			end

		5'd17:	// encryption/decryption continuation
			begin
				input_1 <= rho_out;
				if (enc)
				  input_2 <= round_keys[2];
				else
				  input_2 <= inv_round_keys[6];
				ctrl <= 5'd18;
			end

		5'd18:
			begin
				input_1 <= rho_out;
				if (enc)
				  input_2 <= round_keys[3];
				else
				  input_2 <= inv_round_keys[5];
				ctrl <= 5'd19;
			end

		5'd19:
			begin
				input_1 <= rho_out;
				if (enc)
				  input_2 <= round_keys[4];
				else
				  input_2 <= inv_round_keys[4];
				ctrl <= 5'd20;
			end

		5'd20:
			begin
				input_1 <= rho_out;
				if (enc)
				  input_2 <= round_keys[5];
				else
				  input_2 <= inv_round_keys[3];
				ctrl <= 5'd21;
			end

		5'd21:
			begin
				input_1 <= rho_out;
				if (enc)
				  input_2 <= round_keys[6];
				else
				  input_2 <= inv_round_keys[2];
				ctrl <= 5'd22;
			end

		5'd22:
			begin
				input_1 <= rho_out;
				if (enc)
				  input_2 <= round_keys[7];
				else
				  input_2 <= inv_round_keys[1];
				ctrl <= 5'd23;
			end

		5'd23:
			begin
				input_1 <= rho_out;
				if (enc)
				  input_2 <= round_keys[8];
				else
				  input_2 <= round_keys[0];
				ctrl <= 5'd0;
				last_round <= 1;  // raise the flag
			end

		default:
			;

	  endcase

end

endmodule