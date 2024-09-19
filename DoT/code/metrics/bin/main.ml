open Core;;
open Sys_unix;;

let check_substring s1 s2 =
    let re = Str.regexp_string s2 in
    try 
        ignore (Str.search_forward re s1 0); 
        true
    with _ -> false

let get_feature line =
    line
    |> String.split_on_chars ~on:['\t']
    |> List.rev
    |> List.hd
    |> Option.value ~default:"ERROR could not find feature label"
    |> String.strip ~drop:(fun x -> List.mem ['('; ')'; ','; '\''] x ~equal:(Char.equal))

let get_values line = 
    let rex = Pcre.regexp
        {|^\((?:\d+.\d+, ){5}\[((?:\(\S* \S* *){100})\],|} in
    try
        let parts = Pcre.exec ~rex line |> Pcre.get_substrings in 
        parts.(1)
    with _ -> "ERROR: could not parse line"

let parse_values values = 
    let rex = Pcre.regexp {|, '\S*|\(|} in 
    Pcre.replace ~rex data
    |> String.split_on_chars ~on:[' ']
    |> List.map ~f:(fun x -> int_of_string x)
;;

let process_line line = 
    let _feature = get_feature line in 

    line 
        |> get_values
        |> parse_values
        |> Printf.printf "%s\n"

let process_file file = 
    let lines = In_channel.read_lines file in 

    (* let metrics = *) 
        lines
    (* temp *)
    |> List.hd
    |> Option.value ~default:"None"

    |> process_line

    (* Printf.printf "%s\n" metrics *)
    (* |> List.map ~f:(fun x -> process_line x) *)

let get_files pattern dir = 
    readdir dir
    |> Array.to_list
    |> List.filter ~f:(fun x -> check_substring x pattern) 
    |> List.map ~f:(fun x -> dir^x)

let () = 
    "../"
    |> get_files "USENIX"

    (* temp *)
    |> List.hd
    |> Option.value ~default:"None"
    |> process_file

    (* |> List.map ~f:(fun x -> file_metrics x) *)
    |> ignore
;;
