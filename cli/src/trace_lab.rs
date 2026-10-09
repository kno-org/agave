//! Local tracing fixtures built from the same fork as the validator. Never alters scheduling.
use solana_connection_cache::client_connection::ClientConnection;
use {solana_client::connection_cache::ConnectionCache, solana_hash::Hash,
    solana_instruction::{AccountMeta,Instruction},solana_keypair::read_keypair_file,
    solana_message::Message,solana_pubkey::Pubkey,solana_signer::Signer,
    solana_transaction::Transaction,std::{error::Error,fs,str::FromStr}};
fn main() -> Result<(),Box<dyn Error>> {
    let args:Vec<_>=std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("sign") => {
            let requests:Vec<serde_json::Value>=serde_json::from_slice(&fs::read(&args[2])?)?;
            let mut output=Vec::new();
            for r in requests {
                let payer=read_keypair_file(r["payer"].as_str().ok_or("payer")?)?;
                let mut keys=vec![payer];
                if let Some(extra)=r["signers"].as_array() {for k in extra {keys.push(read_keypair_file(k.as_str().ok_or("signer")?)?);}}
                let ixs:Vec<Instruction>=r["instructions"].as_array().ok_or("instructions")?.iter().map(|i| -> Result<_,Box<dyn Error>> {
                    let accounts=i["accounts"].as_array().ok_or("accounts")?.iter().map(|a| -> Result<_,Box<dyn Error>> {Ok(AccountMeta {pubkey:Pubkey::from_str(a["address"].as_str().ok_or("address")?)?,is_signer:a["signer"].as_bool().unwrap_or(false),is_writable:a["writable"].as_bool().unwrap_or(false)})}).collect::<Result<Vec<_>,_>>()?;
                    Ok(Instruction {program_id:Pubkey::from_str(i["program"].as_str().ok_or("program")?)?,accounts,data:hex::decode(i["hex"].as_str().ok_or("hex")?)?})
                }).collect::<Result<_,_>>()?;
                solk_trace::client("test.signing.begin",solk_trace::json!({"payer":keys[0].pubkey().to_string()}),None,file!());
                let message=Message::new(&ixs,Some(&keys[0].pubkey()));
                let signers:Vec<&dyn Signer>=keys.iter().map(|k|k as &dyn Signer).collect();
                let tx=Transaction::new(&signers,message,Hash::from_str(r["blockhash"].as_str().ok_or("blockhash")?)?);
                let wire=bincode::serialize(&tx)?;
                output.push(serde_json::json!({"signature":tx.signatures[0].to_string(),"hex":hex::encode(&wire),"payer":keys[0].pubkey().to_string()}));
            }
            println!("{}",serde_json::to_string(&output)?);
        },
        Some("quic") => {
            let identity=read_keypair_file(&args[2])?;
            let peer=args[3].parse()?;
            let wires:Vec<String>=serde_json::from_slice(&fs::read(&args[4])?)?;
            let buffers=wires.iter().map(hex::decode).collect::<Result<Vec<_>,_>>()?;
            let cache=ConnectionCache::new_with_client_options("solk-trace-fixture",1,None,Some((&identity,"0.0.0.0".parse()?)),None);
            let connection=cache.get_connection(&peer);
            connection.send_data_batch(&buffers)?;
            println!("{}",serde_json::json!({"sent":buffers.len(),"peer":peer.to_string(),"identity":identity.pubkey().to_string()}));
        },
        Some("ata") => {
            let wallet=Pubkey::from_str(&args[2])?;let mint=Pubkey::from_str(&args[3])?;let token=Pubkey::from_str(&args[4])?;
            let program=Pubkey::from_str("ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL")?;
            println!("{}",Pubkey::find_program_address(&[wallet.as_ref(),token.as_ref(),mint.as_ref()],&program).0);
        },
        _=>return Err("Usage: solk-trace-lab sign request.json | quic identity.json host:port wires.json | ata wallet mint token".into())
    }
    solk_trace::flush();Ok(())
}
