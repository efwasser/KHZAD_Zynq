%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
Zynq-7000 based Implementation of the KHAZAD Block Cipher
Yossef Shitzer & Efraim Wasserman
Jerusalem College of Technology - Lev Academic Center (JCT)
Department of electrical and electronic engineering
2018
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
This MATLAB script gets the original test-vectors results file, 
and generates the simplified easy-to-use file "KHAZAD_test_vectors_simple.txt".
The script can be used for every input file with similar format.
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%
clear all

input_file = fopen('khazad-tweak-test-vectors.txt','r');
line = fgetl(input_file);
keys = [];
plains = [];
ciphers = [];

while ischar(line)
    if ~isempty(strfind(line,'key='))
        keys = [keys regexp(line, 'key=', 'split')];
    end
    if  ~isempty(strfind(line,'plain='))
        plains = [plains regexp(line, 'plain=', 'split')]; 
    end
    if ~isempty(strfind(line,'cipher='))
        ciphers = [ciphers regexp(line, 'cipher=', 'split')];
    end
    line = fgetl(input_file);
end
fclose(input_file);

output_file = fopen('KHAZAD_test_vectors_simple.txt','w');
formatSpec = '%s %s %s\r\n';
for i = 2:2:length(keys)
    fprintf(output_file, formatSpec, keys{i}, plains{i}, ciphers{i});
end
fclose(output_file);