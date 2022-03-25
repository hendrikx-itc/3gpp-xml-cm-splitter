use std::fs::File;
use std::io::Write;
use std::io::{BufReader, BufWriter};
use std::path::PathBuf;

extern crate clap;
use clap::{crate_authors, crate_description, crate_version, App, Arg};

#[macro_use]
extern crate log;
extern crate env_logger;

extern crate serde_derive;

extern crate quick_xml;
use quick_xml::events::{BytesEnd, BytesStart, Event};

use chrono::DateTime;

use sha2::{Digest, Sha256};
use tee_readwrite::TeeWriter;

fn main() {
    let matches = App::new("Topology Splitter")
        .version(crate_version!())
        .author(crate_authors!())
        .about(crate_description!())
        .arg(
            Arg::with_name("output_directory")
                .short("o")
                .long("output-directory")
                .help("Directory where chunks will be written")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("INPUT")
                .help("Sets the input file to use")
                .required(true),
        )
        .get_matches();

    let mut env_logger_builder = env_logger::builder();
    env_logger_builder.format_timestamp(None);
    env_logger_builder.init();

    let file_path = matches.value_of("INPUT").unwrap();

    info!("Using input file: {}", &file_path);

    let output_directory = matches.value_of("output_directory").unwrap_or("/tmp");

    info!("Writing output to: {}", &output_directory);

    let result = split_file(file_path, output_directory);

    match result {
        Ok(chunk_count) => info!("Done splitting into {} chunks", chunk_count),
        Err(e) => error!("{}", e),
    }
}

fn split_file(file_path: &str, output_directory: &str) -> Result<i64, String> {
    let mut chunk_count: i64 = 0;

    let mut f = File::open(&file_path)
        .map_err(|e| String::from(format!("Could not open file {}: {}", file_path, e)))?;

    let timestamp = extract_timestamp(&mut f)?;

    let buf_reader = BufReader::new(f);

    let mut reader = quick_xml::Reader::from_reader(buf_reader);

    let mut buf = Vec::new();

    let mut context_collected = false;
    let mut context: Vec<quick_xml::events::Event> = Vec::new();

    loop {
        match reader.read_event(&mut buf) {
            Ok(e) => {
                let ev = e.clone().into_owned();
                if !context_collected {
                    context.push(ev.clone());
                }

                match e {
                    Event::Start(start_event) => {
                        if start_event.name() == b"xn:MeContext" {
                            if !context_collected {
                                context.pop();
                                context_collected = true;
                            }

                            let mut enb_context = context.clone();
                            enb_context.push(ev);

                            for attr in start_event.attributes().map(|a| a.unwrap()) {
                                if attr.key == b"id" {
                                    let v = attr.unescape_and_decode_value(&reader).unwrap();

                                    info!("{}", &v);

                                    let hash = process_chunk(
                                        output_directory,
                                        &enb_context,
                                        &mut reader,
                                        v,
                                        timestamp,
                                    )?;

                                    chunk_count += 1;

                                    println!("- {}", hash);
                                }
                            }
                        }
                    }
                    Event::End(_) => {}
                    Event::Eof => {
                        // At the end of the file, exit the loop
                        break;
                    }
                    _ => (),
                }
            }
            Err(e) => {
                return Err(String::from(format!(
                    "Error at position {}: {:?}",
                    reader.buffer_position(),
                    e
                )));
            }
        }

        buf.clear();
    }

    Ok(chunk_count)
}

fn extract_timestamp<T>(reader: &mut T) -> Result<DateTime<chrono::FixedOffset>, String>
where
    T: std::io::Read + std::io::Seek,
{
    reader.seek(std::io::SeekFrom::End(-100)).map_err(|e| {
        String::from(format!(
            "Could not seek back 100 bytes from the end of the file: {}",
            e
        ))
    })?;

    let mut buf: Vec<u8> = Vec::new();

    reader
        .read_to_end(&mut buf)
        .map_err(|e| String::from(format!("Could read file: {}", e)))?;

    reader
        .seek(std::io::SeekFrom::Start(0))
        .map_err(|e| String::from(format!("Could not seek to file start: {}", e)))?;

    let text = std::str::from_utf8(&mut buf).unwrap();

    let timestamp_re = regex::Regex::new(r#"<fileFooter dateTime="(.*)"/>"#).unwrap();

    let captures = timestamp_re.captures(text);

    let timestamp_str = captures.unwrap().get(1).map_or("", |m| m.as_str());

    let timestamp = DateTime::parse_from_rfc3339(timestamp_str).map_err(|e| {
        String::from(format!(
            "Could not parse timestamp '{}': {}",
            timestamp_str, e
        ))
    })?;

    Ok(timestamp)
}

fn process_chunk(
    output_directory: &str,
    context: &Vec<Event>,
    reader: &mut quick_xml::Reader<BufReader<File>>,
    enodeb: String,
    timestamp: DateTime<chrono::FixedOffset>,
) -> Result<String, String> {
    let mut buf = Vec::new();

    let mut level = 1;

    let mut out_file_path = PathBuf::from(output_directory);
    out_file_path.push(format!("{}/{}.xml", output_directory, &enodeb));

    let mut out_file = File::create(&out_file_path).map_err(|e| {
        String::from(format!(
            "Could not create chunk file '{}': {}",
            out_file_path.to_string_lossy(),
            e
        ))
    })?;

    let mut hash: Vec<u8> = Vec::with_capacity(32);

    let mut sha256 = Sha256::new();

    {
        let tee_writer = TeeWriter::new(&mut sha256, &mut out_file);

        let buf_writer = BufWriter::new(tee_writer);
        let mut writer = quick_xml::Writer::new(buf_writer);

        for context_event in context {
            writer.write_event(context_event).unwrap();
        }

        loop {
            match reader.read_event(&mut buf) {
                Ok(e) => {
                    writer.write_event(&e).unwrap();

                    match e {
                        Event::Start(_start_event) => {
                            level += 1;
                        }
                        Event::End(_) => {
                            level -= 1;
                            if level == 0 {
                                break;
                            }
                        }
                        Event::Eof => break,
                        _ => (),
                    }
                }
                Err(e) => panic!("Error at position {}: {:?}", reader.buffer_position(), e),
            }

            buf.clear();
        }
    }

    let result = sha256.result();

    hash.write(&result)
        .map_err(|e| String::from(format!("Could not write hash to buffer: {}", e)))?;

    let buf_end_writer = BufWriter::new(&mut out_file);
    let mut end_writer = quick_xml::Writer::new(buf_end_writer);

    for e in context_end(context, &timestamp) {
        end_writer.write_event(e).unwrap();
    }

    let mut hash_out_file_path = PathBuf::from(output_directory);
    hash_out_file_path.push(format!("{}/{}.hash", output_directory, &enodeb));

    let mut hash_out_file = File::create(&hash_out_file_path).map_err(|e| {
        String::from(format!(
            "Could not create hash file '{}': {}",
            hash_out_file_path.to_string_lossy(),
            e
        ))
    })?;

    let hex_string = to_hex_string(hash);

    hash_out_file
        .write(hex_string.as_bytes())
        .map_err(|e| String::from(format!("Could not write hash to file: {}", e)))?;

    Ok(hex_string)
}

pub fn to_hex_string(bytes: Vec<u8>) -> String {
    let strs: Vec<String> = bytes.iter().map(|b| format!("{:02x}", b)).collect();
    strs.join("")
}

// Reverse the context start and translate any start tags to corresponding end tags
fn context_end<'a>(
    context_start: &Vec<Event<'a>>,
    timestamp: &DateTime<chrono::FixedOffset>,
) -> Vec<Event<'a>> {
    let mut result: Vec<Event> = Vec::new();

    for context_event in context_start.iter().rev().skip(1) {
        match context_event {
            Event::Start(e) => {
                // Add a footer right before bulkCmConfigDataFile end
                if e.name() == b"bulkCmConfigDataFile" {
                    let footer_name = b"fileFooter".to_vec();
                    let length = footer_name.len();
                    let mut footer = BytesStart::owned(footer_name, length);

                    footer.push_attribute(("dateTime", timestamp.to_rfc3339().as_str()));

                    result.push(Event::Empty(footer));
                }

                let tag = e.name().clone();
                let e = BytesEnd::owned(tag.to_vec());

                result.push(Event::End(e));
            }
            _ => (),
        }
    }

    result
}
