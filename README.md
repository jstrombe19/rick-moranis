# Rick Moranis

Honey, I shrunk your files!

Hacky workaround to chunk and then reassemble files of arbitrary types.

### Motivation

This really came about because of some PitA restrictions on a particular project. I needed to be able to share large files and the existing channels were not able to support that.

### Compilation
This project is intended to be compiled into two separate executables to handle each portion of the file handling.

#### Linux
File splitting executable:
`gcc -o filesplit filesplit.c -lcrypto`

File joining executable:
`gcc -o filejoin filejoin.c -lcrypto`

### Usage

#### File Splitting
`./filesplit <filepath> <maximum_chunk_size_in_bytes>`

#### File Joining
`./filejoin <original_filename_base> <number_of_chunks> <reassembled_file_name> <path_to_sha256sum_of_original_file>`

