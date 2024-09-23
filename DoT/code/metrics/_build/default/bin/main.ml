open Core;;
open Sys_unix;;

let check_substring s1 s2 =
    let re = Str.regexp_string s2 in
    try 
        ignore (Str.search_forward re s1 0); 
        true
    with _ -> false

let extract_scope s = 
    let rex = Pcre.regexp
        {|(.*)_((?:A|root|IS|T|S|resol).*)$|} in
    try
        let parts = Pcre.exec ~rex s |> Pcre.get_substrings in 
        parts.(1), parts.(2)
    with _ -> s, "global"

let get_feature line =
    line
    |> String.split_on_chars ~on:['\t']
    |> List.rev
    |> List.hd
    |> Option.value ~default:"ERROR could not find feature label"
    |> String.strip ~drop:(fun x -> List.mem ['('; ')'; ','; '\''] x ~equal:(Char.equal))
    |> extract_scope

let get_values line = 
    let rex = Pcre.regexp
        {|^\((?:\d+.\d+, ){5}\[((?:\(\S* \S* *){100})\],|} in
    try
        let parts = Pcre.exec ~rex line |> Pcre.get_substrings in 
        parts.(1)
    with _ -> "ERROR: could not parse line"

let parse_values data = 
    let rex = Pcre.regexp {|, '\S*|\(|} in 
    Pcre.replace ~rex data
    |> String.split_on_chars ~on:[' ']
    |> List.map ~f:(fun x -> int_of_string x)
;;

let calc_recall_at_k k values = 
    let len = values 
    |> List.length
    |> float_of_int in 
    let good = values
    (* Must remove values that are 0. These are values that could not be found  *)
    |> List.filter ~f:(fun x -> x <= k && x <> 0)
    |> List.length
    |> float_of_int
    in 
    (* Printf.printf "len:%f\tgood:%f\n" len good; *)
    good /. len
;;

let calc_precision_at_k k values = 
    let recall = calc_recall_at_k k values in 
    (* Because there can only be one good value, we can scale this value based 
       on the number of good results we have seen  *)
    recall /. (float_of_int k)
;;

let calc_f1_at_k k values = 
    let recall = calc_recall_at_k k values in 
    let precision = calc_precision_at_k k values in 
    let beta = 1. in 
    let top = (1. +. beta *. beta) *. recall *. precision in 
    let bottom = (beta *. beta *. precision) +. recall in 
    top /. bottom
;;

let process_line line = 
    let feature, scope = get_feature line in 

    let values = line
        |> get_values
        |> parse_values in 

    let aux k = 
        let recall = calc_recall_at_k k values in 
        let precision = calc_precision_at_k k values in 
        let f1 = calc_f1_at_k k values in 

        let (json_result: Yojson.Basic.t)= 
            `Assoc [
                (string_of_int k, `List [
                    `Assoc [("recall", `Float recall)];
                    `Assoc [("precision", `Float precision)];
                    `Assoc [("f1", `Float f1)]
                ])] in

        json_result
    in
    let (empty_json: Yojson.Basic.t) = `Assoc [] in 

    let m = [1; 2; 4; 8;]
        |> List.map ~f:(fun k -> aux k)
        |> List.fold_left ~init:empty_json ~f:(fun x y -> 
                Yojson.Basic.Util.combine x y)
    in 
    `Assoc [(scope^":"^feature, `List[(Yojson.Basic.Util.combine (`Assoc [("scope", `String scope)]) m)])]


let process_file file = 
    let (empty_json: Yojson.Basic.t) = `Assoc [("file", `String file)] in 

    In_channel.read_lines file
        |> List.map ~f:(fun x -> process_line x)
        |> List.fold_left ~init:empty_json ~f:(fun x y -> 
                Yojson.Basic.Util.combine x y)
        |> Yojson.Basic.pretty_to_channel stdout
        |> ignore


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
    (* in *) 
    (* Printf.printf "%s\n" file; *)

    (* file *)
    |> process_file

    (* |> List.map ~f:(fun x -> file_metrics x) *)
    |> ignore
;;
