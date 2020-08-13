/**
  @defgroup eosclienttool

  @section intro Introduction to cleos

  `cleos` is a command line tool that interfaces with the REST api exposed by @ref nodeos. In order to use `cleos` you will need to
  have a local copy of `nodeos` running and configured to load the 'eosio::chain_api_plugin'.

   cleos contains documentation for all of its commands. For a list of all commands known to cleos, simply run it with no arguments:
```
$ ./cleos
Command Line Interface to EOSIO Client
Usage: programs/cleos/cleos [OPTIONS] SUBCOMMAND

Options:
  -h,--help                   Print this help message and exit
  -u,--url TEXT=http://localhost:8888/
                              the http/https URL where nodeos is running
  --wallet-url TEXT=http://localhost:8888/
                              the http/https URL where keosd is running
  -r,--header                 pass specific HTTP header, repeat this option to pass multiple headers
  -n,--no-verify              don't verify peer certificate when using HTTPS
  -v,--verbose                output verbose errors and action output

Subcommands:
  version                     Retrieve version information
  create                      Create various items, on and off the blockchain
  get                         Retrieve various items and information from the blockchain
  set                         Set or update blockchain state
  transfer                    Transfer tokens from account to account
  net                         Interact with local p2p network connections
  wallet                      Interact with local wallet
  sign                        Sign a transaction
  push                        Push arbitrary transactions to the blockchain
  multisig                    Multisig contract commands

```
To get help with any particular subcommand, run it with no arguments as well:
```
$ ./cleos create
Create various items, on and off the blockchain
Usage: ./cleos create SUBCOMMAND

Subcommands:
  key                         Create a new keypair and print the public and private keys
  account                     Create a new account on the blockchain (assumes system contract does not restrict RAM usage)

$ ./cleos create account
Create a new account on the blockchain (assumes system contract does not restrict RAM usage)
Usage: ./cleos create account [OPTIONS] creator name OwnerKey ActiveKey

Positionals:
  creator TEXT                The name of the account creating the new account
  name TEXT                   The name of the new account
  OwnerKey TEXT               The owner public key for the new account
  ActiveKey TEXT              The active public key for the new account

Options:
  -x,--expiration             set the time in seconds before a transaction expires, defaults to 30s
  -f,--force-unique           force the transaction to be unique. this will consume extra bandwidth and remove any protections against accidently issuing the same transaction multiple times
  -s,--skip-sign              Specify if unlocked wallet keys should be used to sign transaction
  -d,--dont-broadcast         don't broadcast transaction to the network (just print to stdout)
  -p,--permission TEXT ...    An account and permission level to authorize, as in 'account@permission' (defaults to 'creator@active')
```
*/

#include <pwd.h>
#include <string>
#include <vector>
#include <regex>
#include <iostream>
#include <fc/crypto/hex.hpp>
#include <fc/variant.hpp>
#include <fc/io/datastream.hpp>
#include <fc/io/json.hpp>
#include <fc/io/console.hpp>
#include <fc/exception/exception.hpp>
#include <fc/variant_object.hpp>
#include <fc/static_variant.hpp>

#include <eosio/chain/name.hpp>
#include <eosio/chain/config.hpp>
#include <eosio/chain/wast_to_wasm.hpp>
#include <eosio/chain/trace.hpp>
#include <eosio/chain_plugin/chain_plugin.hpp>
#include <eosio/chain/contract_types.hpp>

#include <eosio/version/version.hpp>

#pragma push_macro("N")
#undef N

#include <boost/asio.hpp>
#include <boost/format.hpp>
#include <boost/dll/runtime_symbol_info.hpp>
#include <boost/filesystem.hpp>
#include <boost/process.hpp>
#include <boost/process/spawn.hpp>
#include <boost/range/algorithm/find_if.hpp>
#include <boost/range/algorithm/sort.hpp>
#include <boost/range/adaptor/transformed.hpp>
#include <boost/algorithm/string/predicate.hpp>
#include <boost/algorithm/string/split.hpp>
#include <boost/range/algorithm/copy.hpp>
#include <boost/algorithm/string/classification.hpp>

#pragma pop_macro("N")

#include <Inline/BasicTypes.h>
#include <IR/Module.h>
#include <IR/Validate.h>
#include <WASM/WASM.h>
#include <Runtime/Runtime.h>

#include <fc/io/fstream.hpp>


#include "localize.hpp"
#include "config.hpp"
#include "httpc.hpp"


using namespace std;
using namespace eosio;
using namespace eosio::chain;
using namespace eosio::client::http;
using namespace eosio::client::localize;
using namespace eosio::client::config;
using namespace boost::filesystem;
using auth_type = fc::static_variant<public_key_type, permission_level>;

FC_DECLARE_EXCEPTION( explained_exception, 9000000, "explained exception, see error log" );
FC_DECLARE_EXCEPTION( localized_exception, 10000000, "an error occured" );
#define EOSC_ASSERT( TEST, ... ) \
  FC_EXPAND_MACRO( \
    FC_MULTILINE_MACRO_BEGIN \
      if( UNLIKELY(!(TEST)) ) \
      {                                                   \
        std::cerr << localized( __VA_ARGS__ ) << std::endl;  \
        FC_THROW_EXCEPTION( explained_exception, #TEST ); \
      }                                                   \
    FC_MULTILINE_MACRO_END \
  )

//copy pasta from keosd's main.cpp
bfs::path determine_home_directory()
{
   bfs::path home;
   struct passwd* pwd = getpwuid(getuid());
   if(pwd) {
      home = pwd->pw_dir;
   }
   else {
      home = getenv("HOME");
   }
   if(home.empty())
      home = "./";
   return home;
}

string url = "http://127.0.0.1:8888/";
string default_wallet_url = "unix://" + (determine_home_directory() / "eosio-wallet" / (string(key_store_executable_name) + ".sock")).string();
string wallet_url; //to be set to default_wallet_url in main
bool no_verify = false;
vector<string> headers;

auto   tx_expiration = fc::seconds(30);
const fc::microseconds abi_serializer_max_time = fc::seconds(10); // No risk to client side serialization taking a long time
string tx_ref_block_num_or_id;
bool   tx_force_unique = false;
bool   tx_dont_broadcast = false;
bool   tx_return_packed = false;
bool   tx_skip_sign = false;
bool   tx_print_json = false;
bool   tx_use_old_rpc = false;
string tx_json_save_file;
bool   print_request = false;
bool   print_response = false;
bool   no_auto_keosd = false;
bool   verbose = false;

uint8_t  tx_max_cpu_usage = 0;
uint32_t tx_max_net_usage = 0;

uint32_t delaysec = 0;

vector<string> tx_permission;

eosio::client::http::http_context context;


vector<chain::permission_level> get_account_permissions(const vector<string>& permissions) {
   auto fixedPermissions = permissions | boost::adaptors::transformed([](const string& p) {
      vector<string> pieces;
      split(pieces, p, boost::algorithm::is_any_of("@"));
      if( pieces.size() == 1 ) pieces.push_back( "active" );
      return chain::permission_level{ .actor = name(pieces[0]), .permission = name(pieces[1]) };
   });
   vector<chain::permission_level> accountPermissions;
   boost::range::copy(fixedPermissions, back_inserter(accountPermissions));
   return accountPermissions;
}

vector<chain::permission_level> get_account_permissions(const vector<string>& permissions, const chain::permission_level& default_permission) {
   if (permissions.empty())
      return vector<chain::permission_level>{default_permission};
   else
      return get_account_permissions(tx_permission);
}

template<typename T>
fc::variant call( const std::string& url,
                  const std::string& path,
                  const T& v ) {
   // std::cout << "call:" << url << ":" << path << std::endl;
   try {
      auto sp = std::make_unique<eosio::client::http::connection_param>(context, parse_url(url) + path, no_verify ? false : true, headers);
      return eosio::client::http::do_http_call(*sp, fc::variant(v), print_request, print_response );
   }
   catch(boost::system::system_error& e) {
      if(url == ::url)
         std::cerr << localized("Failed to connect to ${n} at ${u}; is ${n} running?", ("n", node_executable_name)("u", url)) << std::endl;
      else if(url == ::wallet_url)
         std::cerr << localized("Failed to connect to ${k} at ${u}; is ${k} running?", ("k", key_store_executable_name)("u", url)) << std::endl;
      throw connection_exception(fc::log_messages{FC_LOG_MESSAGE(error, "cpp exception")});
   }
}

template<typename T>
fc::variant call( const std::string& path,
                  const T& v ) { return call( url, path, fc::variant(v) ); }

template<>
fc::variant call( const std::string& url,
                  const std::string& path) { return call( url, path, fc::variant() ); }

eosio::chain_apis::read_only::get_info_results get_info() {
   return call(url, get_info_func).as<eosio::chain_apis::read_only::get_info_results>();
}

string generate_nonce_string() {
   return fc::to_string(fc::time_point::now().time_since_epoch().count());
}

chain::action generate_nonce_action() {
   return chain::action( {}, config::null_account_name, name("nonce"), fc::raw::pack(fc::time_point::now().time_since_epoch().count()));
}

//resolver for ABI serializer to decode actions in proposed transaction in multisig contract
auto abi_serializer_resolver = [](const name& account) -> fc::optional<abi_serializer> {
  static unordered_map<account_name, fc::optional<abi_serializer> > abi_cache;
  auto it = abi_cache.find( account );
  if ( it == abi_cache.end() ) {

    const auto raw_abi_result = call(get_raw_abi_func, fc::mutable_variant_object("account_name", account));
    const auto raw_abi_blob = raw_abi_result["abi"].as_blob().data;
    fc::optional<abi_serializer> abis;
    if (raw_abi_blob.size() != 0) {
      abis.emplace(fc::raw::unpack<abi_def>(raw_abi_blob), abi_serializer::create_yield_function( abi_serializer_max_time ));
    } else {
      std::cerr << "ABI for contract " << account.to_string() << " not found. Action data will be shown in hex only." << std::endl;
    }
    abi_cache.emplace( account, abis );

    return abis;
  }

  return it->second;
};


fc::variant determine_required_keys(const signed_transaction& trx) {
   // TODO better error checking
   //wdump((trx));
   const auto& public_keys = call(wallet_url, wallet_public_keys);
   auto get_arg = fc::mutable_variant_object
           ("transaction", (transaction)trx)
           ("available_keys", public_keys);
   const auto& required_keys = call(get_required_keys, get_arg);
   return required_keys["required_keys"];
}

void sign_transaction(signed_transaction& trx, fc::variant& required_keys, const chain_id_type& chain_id) {
   fc::variants sign_args = {fc::variant(trx), required_keys, fc::variant(chain_id)};
   const auto& signed_trx = call(wallet_url, wallet_sign_trx, sign_args);
   trx = signed_trx.as<signed_transaction>();
}

fc::variant push_transaction( signed_transaction& trx, const std::vector<public_key_type>& signing_keys = std::vector<public_key_type>(),
                              packed_transaction::compression_type compression = packed_transaction::compression_type::none, const std::vector<private_key_type>& private_sign_key = {} ) {
   auto info = get_info();

   if (trx.signatures.size() == 0) { // #5445 can't change txn content if already signed
      trx.expiration = info.head_block_time + tx_expiration;

      // Set tapos, default to last irreversible block if it's not specified by the user
      block_id_type ref_block_id = info.last_irreversible_block_id;
      try {
         fc::variant ref_block;
         if (!tx_ref_block_num_or_id.empty()) {
            ref_block = call(get_block_func, fc::mutable_variant_object("block_num_or_id", tx_ref_block_num_or_id));
            ref_block_id = ref_block["id"].as<block_id_type>();
         }
      } EOS_RETHROW_EXCEPTIONS(invalid_ref_block_exception, "Invalid reference block num or id: ${block_num_or_id}", ("block_num_or_id", tx_ref_block_num_or_id));
      trx.set_reference_block(ref_block_id);

      if (tx_force_unique) {
         trx.context_free_actions.emplace_back( generate_nonce_action() );
      }

      trx.max_cpu_usage_ms = tx_max_cpu_usage;
      trx.max_net_usage_words = (tx_max_net_usage + 7)/8;
      trx.delay_sec = delaysec;
   }

   if (!tx_skip_sign) {
      if(private_sign_key.empty()){
         fc::variant required_keys;
         if (signing_keys.size() > 0) {
            required_keys = fc::variant(signing_keys);
         }
         else {
            required_keys = determine_required_keys(trx);
         }
         sign_transaction(trx, required_keys, info.chain_id);
      }
      else{
         fc::optional<chain_id_type> chain_id;
         auto info = get_info();
         chain_id = info.chain_id;
         for(auto& k : private_sign_key){
            trx.sign(k,*chain_id);
         }
      }
   }

   if (!tx_dont_broadcast) {
      if (tx_use_old_rpc) {
         return call(push_txn_func, packed_transaction(trx, compression));
      } else {
         try {
            return call(send_txn_func, packed_transaction(trx, compression));
         }
         catch (chain::missing_chain_api_plugin_exception &) {
            std::cerr << "New RPC send_transaction may not be supported. Add flag --use-old-rpc to use old RPC push_transaction instead." << std::endl;
            throw;
         }
      }
   } else {
      if (!tx_return_packed) {
         try {
            fc::variant unpacked_data_trx;
            abi_serializer::to_variant(trx, unpacked_data_trx, abi_serializer_resolver, abi_serializer::create_yield_function( abi_serializer_max_time ));
            return unpacked_data_trx;
         } catch (...) {
            return fc::variant(trx);
         }
      } else {
        return fc::variant(packed_transaction(trx, compression));
      }
   }
}

fc::variant push_actions(std::vector<chain::action>&& actions, packed_transaction::compression_type compression = packed_transaction::compression_type::none, const std::vector<public_key_type>& signing_keys = std::vector<public_key_type>(), const std::vector<private_key_type>& private_sign_key = {} ) {
   signed_transaction trx;
   trx.actions = std::forward<decltype(actions)>(actions);

   return push_transaction(trx, signing_keys, compression,private_sign_key);
}

void print_action( const fc::variant& at ) {
   const auto& receipt = at["receipt"];
   auto receiver = receipt["receiver"].as_string();
   const auto& act = at["act"].get_object();
   auto code = act["account"].as_string();
   auto func = act["name"].as_string();
   auto args = fc::json::to_string( act["data"], fc::time_point::maximum() );
   auto console = at["console"].as_string();

   /*
   if( code == "eosio" && func == "setcode" )
      args = args.substr(40)+"...";
   if( name(code) == config::system_account_name && func == "setabi" )
      args = args.substr(40)+"...";
   */
   if( args.size() > 100 ) args = args.substr(0,100) + "...";
   cout << "#" << std::setw(14) << right << receiver << " <= " << std::setw(28) << std::left << (code +"::" + func) << " " << args << "\n";
   if( console.size() ) {
      std::stringstream ss(console);
      string line;
      while( std::getline( ss, line ) ) {
         cout << ">> " << line << "\n";
         if( !verbose ) break;
      }
   }
}

bytes variant_to_bin( const account_name& account, const action_name& action, const fc::variant& action_args_var ) {
   auto abis = abi_serializer_resolver( account );
   FC_ASSERT( abis.valid(), "No ABI found for ${contract}", ("contract", account));

   auto action_type = abis->get_action_type( action );
   FC_ASSERT( !action_type.empty(), "Unknown action ${action} in contract ${contract}", ("action", action)( "contract", account ));
   return abis->variant_to_binary( action_type, action_args_var, abi_serializer::create_yield_function( abi_serializer_max_time ) );
}

fc::variant bin_to_variant( const account_name& account, const action_name& action, const bytes& action_args) {
   auto abis = abi_serializer_resolver( account );
   FC_ASSERT( abis.valid(), "No ABI found for ${contract}", ("contract", account));

   auto action_type = abis->get_action_type( action );
   FC_ASSERT( !action_type.empty(), "Unknown action ${action} in contract ${contract}", ("action", action)( "contract", account ));
   return abis->binary_to_variant( action_type, action_args, abi_serializer::create_yield_function( abi_serializer_max_time ) );
}

fc::variant json_from_file_or_string(const string& file_or_str, fc::json::parse_type ptype = fc::json::parse_type::legacy_parser)
{
   regex r("^[ \t]*[\{\[]");
   if ( !regex_search(file_or_str, r) && fc::is_regular_file(file_or_str) ) {
      try {
         return fc::json::from_file(file_or_str, ptype);
      } EOS_RETHROW_EXCEPTIONS(json_parse_exception, "Fail to parse JSON from file: ${file}", ("file", file_or_str));

   } else {
      try {
         return fc::json::from_string(file_or_str, ptype);
      } EOS_RETHROW_EXCEPTIONS(json_parse_exception, "Fail to parse JSON from string: ${string}", ("string", file_or_str));
   }
}

bytes json_or_file_to_bin( const account_name& account, const action_name& action, const string& data_or_filename ) {
   fc::variant action_args_var;
   if( !data_or_filename.empty() ) {
      action_args_var = json_from_file_or_string(data_or_filename, fc::json::parse_type::relaxed_parser);
   }
   return variant_to_bin( account, action, action_args_var );
}

void print_action_tree( const fc::variant& action ) {
   print_action( action );
   if( action.get_object().contains( "inline_traces" ) ) {
      const auto& inline_traces = action["inline_traces"].get_array();
      for( const auto& t : inline_traces ) {
         print_action_tree( t );
      }
   }
}

void print_result( const fc::variant& result ) { try {
      if (result.is_object() && result.get_object().contains("processed")) {
         const auto& processed = result["processed"];
         const auto& transaction_id = processed["id"].as_string();
         string status = "failed";
         int64_t net = -1;
         int64_t cpu = -1;
         if( processed.get_object().contains( "receipt" )) {
            const auto& receipt = processed["receipt"];
            if( receipt.is_object()) {
               status = receipt["status"].as_string();
               net = receipt["net_usage_words"].as_int64() * 8;
               cpu = receipt["cpu_usage_us"].as_int64();
            }
         }

         cerr << status << " transaction: " << transaction_id << "  ";
         if( net < 0 ) {
            cerr << "<unknown>";
         } else {
            cerr << net;
         }
         cerr << " bytes  ";
         if( cpu < 0 ) {
            cerr << "<unknown>";
         } else {
            cerr << cpu;
         }

         cerr << " us\n";

         if( status == "failed" ) {
            auto soft_except = processed["except"].as<fc::optional<fc::exception>>();
            if( soft_except ) {
               edump((soft_except->to_detail_string()));
            }
         } else {
            const auto& actions = processed["action_traces"].get_array();
            for( const auto& a : actions ) {
               print_action_tree( a );
            }
            wlog( "\rwarning: transaction executed locally, but may not be confirmed by the network yet" );
         }
      } else {
         cerr << fc::json::to_pretty_string( result ) << endl;
      }
} FC_CAPTURE_AND_RETHROW( (result) ) }

using std::cout;
std::string send_actions(std::vector<chain::action>&& actions, const std::vector<public_key_type>& signing_keys = std::vector<public_key_type>(), packed_transaction::compression_type compression = packed_transaction::compression_type::none, const std::vector<private_key_type>& private_sign_key = {} ) {
   auto result = push_actions( move(actions), compression, signing_keys,private_sign_key);

   string jsonstr = fc::json::to_pretty_string( result );
   return jsonstr;
}

chain::permission_level to_permission_level(const std::string& s) {
   auto at_pos = s.find('@');
   return permission_level { name(s.substr(0, at_pos)), name(s.substr(at_pos + 1)) };
}

chain::action create_newaccount(const name& creator, const name& newaccount, auth_type owner, auth_type active) {
   return action {
      get_account_permissions(tx_permission, {creator,config::active_name}),
      eosio::chain::newaccount{
         .creator      = creator,
         .name         = newaccount,
         .owner        = owner.contains<public_key_type>() ? authority(owner.get<public_key_type>()) : authority(owner.get<permission_level>()),
         .active       = active.contains<public_key_type>() ? authority(active.get<public_key_type>()) : authority(active.get<permission_level>())
      }
   };
}

chain::action create_action(const vector<permission_level>& authorization, const account_name& code, const action_name& act, const fc::variant& args) {
   return chain::action{authorization, code, act, variant_to_bin(code, act, args)};
}

chain::action create_buyram(const name& creator, const name& newaccount, const asset& quantity) {
   fc::variant act_payload = fc::mutable_variant_object()
         ("payer", creator.to_string())
         ("receiver", newaccount.to_string())
         ("quant", quantity.to_string());
   return create_action(get_account_permissions(tx_permission, {creator,config::active_name}),
                        config::system_account_name, N(buyram), act_payload);
}

chain::action create_buyrambytes(const name& creator, const name& newaccount, uint32_t numbytes) {
   fc::variant act_payload = fc::mutable_variant_object()
         ("payer", creator.to_string())
         ("receiver", newaccount.to_string())
         ("bytes", numbytes);
   return create_action(get_account_permissions(tx_permission, {creator,config::active_name}),
                        config::system_account_name, N(buyrambytes), act_payload);
}

chain::action create_delegate(const name& from, const name& receiver, const asset& net, const asset& cpu, bool transfer) {
   fc::variant act_payload = fc::mutable_variant_object()
         ("from", from.to_string())
         ("receiver", receiver.to_string())
         ("stake_net_quantity", net.to_string())
         ("stake_cpu_quantity", cpu.to_string())
         ("transfer", transfer);
   return create_action(get_account_permissions(tx_permission, {from,config::active_name}),
                        config::system_account_name, N(delegatebw), act_payload);
}

fc::variant regproducer_variant(const account_name& producer, const public_key_type& key, const string& url, uint16_t location) {
   return fc::mutable_variant_object()
            ("producer", producer)
            ("producer_key", key)
            ("url", url)
            ("location", location)
            ;
}

chain::action create_open(const string& contract, const name& owner, symbol sym, const name& ram_payer) {
   auto open_ = fc::mutable_variant_object
      ("owner", owner)
      ("symbol", sym)
      ("ram_payer", ram_payer);
    return action {
      get_account_permissions(tx_permission, {ram_payer, config::active_name}),
      name(contract), N(open), variant_to_bin( name(contract), N(open), open_ )
   };
}

chain::action create_transfer(const string& contract, const name& sender, const name& recipient, asset amount, const string& memo ) {

   auto transfer = fc::mutable_variant_object
      ("from", sender)
      ("to", recipient)
      ("quantity", amount)
      ("memo", memo);

   return action {
      get_account_permissions(tx_permission, {sender,config::active_name}),
      name(contract), N(transfer), variant_to_bin( name(contract), N(transfer), transfer )
   };
}

chain::action create_setabi(const name& account, const bytes& abi) {
   return action {
      get_account_permissions(tx_permission, {account,config::active_name}),
      setabi{
         .account   = account,
         .abi       = abi
      }
   };
}

chain::action create_setcode(const name& account, const bytes& code) {
   return action {
      get_account_permissions(tx_permission, {account,config::active_name}),
      setcode{
         .account   = account,
         .vmtype    = 0,
         .vmversion = 0,
         .code      = code
      }
   };
}

chain::action create_updateauth(const name& account, const name& permission, const name& parent, const authority& auth) {
   return action { get_account_permissions(tx_permission, {account,config::active_name}),
                   updateauth{account, permission, parent, auth}};
}

chain::action create_deleteauth(const name& account, const name& permission) {
   return action { get_account_permissions(tx_permission, {account,config::active_name}),
                   deleteauth{account, permission}};
}

chain::action create_linkauth(const name& account, const name& code, const name& type, const name& requirement) {
   return action { get_account_permissions(tx_permission, {account,config::active_name}),
                   linkauth{account, code, type, requirement}};
}

chain::action create_unlinkauth(const name& account, const name& code, const name& type) {
   return action { get_account_permissions(tx_permission, {account,config::active_name}),
                   unlinkauth{account, code, type}};
}

authority parse_json_authority(const std::string& authorityJsonOrFile) {
   fc::variant authority_var = json_from_file_or_string(authorityJsonOrFile);
   try {
      return authority_var.as<authority>();
   } EOS_RETHROW_EXCEPTIONS(authority_type_exception, "Invalid authority format '${data}'",
                            ("data", fc::json::to_string(authority_var, fc::time_point::maximum())))
}

bool is_public_key_str(const std::string& potential_key_str) {
   return boost::istarts_with(potential_key_str, "EOS") || boost::istarts_with(potential_key_str, "PUB_R1") ||  boost::istarts_with(potential_key_str, "PUB_K1") ||  boost::istarts_with(potential_key_str, "PUB_WA");
}

authority parse_json_authority_or_key(const std::string& authorityJsonOrFile) {
   if (is_public_key_str(authorityJsonOrFile)) {
      try {
         return authority(public_key_type(authorityJsonOrFile));
      } EOS_RETHROW_EXCEPTIONS(public_key_type_exception, "Invalid public key: ${public_key}", ("public_key", authorityJsonOrFile))
   } else {
      auto result = parse_json_authority(authorityJsonOrFile);
      EOS_ASSERT( eosio::chain::validate(result), authority_type_exception, "Authority failed validation! ensure that keys, accounts, and waits are sorted and that the threshold is valid and satisfiable!");
      return result;
   }
}

asset to_asset( account_name code, const string& s ) {
   static map< pair<account_name, eosio::chain::symbol_code>, eosio::chain::symbol> cache;
   auto a = asset::from_string( s );
   eosio::chain::symbol_code sym = a.get_symbol().to_symbol_code();
   auto it = cache.find( make_pair(code, sym) );
   auto sym_str = a.symbol_name();
   if ( it == cache.end() ) {
      auto json = call(get_currency_stats_func, fc::mutable_variant_object("json", false)
                       ("code", code)
                       ("symbol", sym_str)
      );
      auto obj = json.get_object();
      auto obj_it = obj.find( sym_str );
      if (obj_it != obj.end()) {
         auto result = obj_it->value().as<eosio::chain_apis::read_only::get_currency_stats_result>();
         auto p = cache.emplace( make_pair( code, sym ), result.max_supply.get_symbol() );
         it = p.first;
      } else {
         EOS_THROW(symbol_type_exception, "Symbol ${s} is not supported by token contract ${c}", ("s", sym_str)("c", code));
      }
   }
   auto expected_symbol = it->second;
   if ( a.decimals() < expected_symbol.decimals() ) {
      auto factor = expected_symbol.precision() / a.precision();
      a = asset( a.get_amount() * factor, expected_symbol );
   } else if ( a.decimals() > expected_symbol.decimals() ) {
      EOS_THROW(symbol_type_exception, "Too many decimal digits in ${a}, only ${d} supported", ("a", a)("d", expected_symbol.decimals()));
   } // else precision matches
   return a;
}

inline asset to_asset( const string& s ) {
   return to_asset( N(eosio.token), s );
}



bool local_port_used() {
    using namespace boost::asio;

    io_service ios;
    local::stream_protocol::endpoint endpoint(wallet_url.substr(strlen("unix://")));
    local::stream_protocol::socket socket(ios);
    boost::system::error_code ec;
    socket.connect(endpoint, ec);

    return !ec;
}

void try_local_port(uint32_t duration) {
   using namespace std::chrono;
   auto start_time = duration_cast<std::chrono::milliseconds>( system_clock::now().time_since_epoch() ).count();
   while ( !local_port_used()) {
      if (duration_cast<std::chrono::milliseconds>( system_clock::now().time_since_epoch()).count() - start_time > duration ) {
         std::cerr << "Unable to connect to " << key_store_executable_name << ", if " << key_store_executable_name << " is running please kill the process and try again.\n";
         throw connection_exception(fc::log_messages{FC_LOG_MESSAGE(error, "Unable to connect to ${k}", ("k", key_store_executable_name))});
      }
   }
}


std::string get_account( const string& accountName, const string& coresym, bool json_format ) {
   std::stringstream sout;
   fc::variant json;
   if (coresym.empty()) {
      json = call(get_account_func, fc::mutable_variant_object("account_name", accountName));
   }
   else {
      json = call(get_account_func, fc::mutable_variant_object("account_name", accountName)("expected_core_symbol", symbol::from_string(coresym)));
   }

   auto res = json.as<eosio::chain_apis::read_only::get_account_results>();
   if (!json_format) {
      asset staked;
      asset unstaking;

      if( res.core_liquid_balance.valid() ) {
         unstaking = asset( 0, res.core_liquid_balance->get_symbol() ); // Correct core symbol for unstaking asset.
         staked = asset( 0, res.core_liquid_balance->get_symbol() );    // Correct core symbol for staked asset.
      }

      sout << "created: " << string(res.created) << std::endl;

      if(res.privileged) sout << "privileged: true" << std::endl;

      constexpr size_t indent_size = 5;
      const string indent(indent_size, ' ');

      sout << "permissions: " << std::endl;
      unordered_map<name, vector<name>/*children*/> tree;
      vector<name> roots; //we don't have multiple roots, but we can easily handle them here, so let's do it just in case
      unordered_map<name, eosio::chain_apis::permission> cache;
      for ( auto& perm : res.permissions ) {
         if ( perm.parent ) {
            tree[perm.parent].push_back( perm.perm_name );
         } else {
            roots.push_back( perm.perm_name );
         }
         auto name = perm.perm_name; //keep copy before moving `perm`, since thirst argument of emplace can be evaluated first
         // looks a little crazy, but should be efficient
         cache.insert( std::make_pair(name, std::move(perm)) );
      }
      std::function<void (account_name, int)> dfs_print = [&]( account_name name, int depth ) -> void {
         auto& p = cache.at(name);
         sout << indent << std::string(depth*3, ' ') << name << ' ' << std::setw(5) << p.required_auth.threshold << ":    ";
         const char *sep = "";
         for ( auto it = p.required_auth.keys.begin(); it != p.required_auth.keys.end(); ++it ) {
            sout << sep << it->weight << ' ' << it->key.to_string();
            sep = ", ";
         }
         for ( auto& acc : p.required_auth.accounts ) {
            sout << sep << acc.weight << ' ' << acc.permission.actor.to_string() << '@' << acc.permission.permission.to_string();
            sep = ", ";
         }
         sout << std::endl;
         auto it = tree.find( name );
         if (it != tree.end()) {
            auto& children = it->second;
            sort( children.begin(), children.end() );
            for ( auto& n : children ) {
               // we have a tree, not a graph, so no need to check for already visited nodes
               dfs_print( n, depth+1 );
            }
         } // else it's a leaf node
      };
      std::sort(roots.begin(), roots.end());
      for ( auto r : roots ) {
         dfs_print( r, 0 );
      }

      auto to_pretty_net = []( int64_t nbytes, uint8_t width_for_units = 5 ) {
         if(nbytes == -1) {
             // special case. Treat it as unlimited
             return std::string("unlimited");
         }

         string unit = "bytes";
         double bytes = static_cast<double> (nbytes);
         if (bytes >= 1024 * 1024 * 1024 * 1024ll) {
             unit = "TiB";
             bytes /= 1024 * 1024 * 1024 * 1024ll;
         } else if (bytes >= 1024 * 1024 * 1024) {
             unit = "GiB";
             bytes /= 1024 * 1024 * 1024;
         } else if (bytes >= 1024 * 1024) {
             unit = "MiB";
             bytes /= 1024 * 1024;
         } else if (bytes >= 1024) {
             unit = "KiB";
             bytes /= 1024;
         }
         std::stringstream ss;
         ss << setprecision(4);
         ss << bytes << " ";
         if( width_for_units > 0 )
            ss << std::left << setw( width_for_units );
         ss << unit;
         return ss.str();
      };



      sout << "memory: " << std::endl
                << indent << "quota: " << std::setw(15) << to_pretty_net(res.ram_quota) << "  used: " << std::setw(15) << to_pretty_net(res.ram_usage) << std::endl << std::endl;

      sout << "net bandwidth: " << std::endl;
      if ( res.total_resources.is_object() ) {
         auto net_total = to_asset(res.total_resources.get_object()["net_weight"].as_string());

         if( net_total.get_symbol() != unstaking.get_symbol() ) {
            // Core symbol of nodeos responding to the request is different than core symbol built into cleos
            unstaking = asset( 0, net_total.get_symbol() ); // Correct core symbol for unstaking asset.
            staked = asset( 0, net_total.get_symbol() ); // Correct core symbol for staked asset.
         }

         if( res.self_delegated_bandwidth.is_object() ) {
            asset net_own =  asset::from_string( res.self_delegated_bandwidth.get_object()["net_weight"].as_string() );
            staked = net_own;

            auto net_others = net_total - net_own;

            sout << indent << "staked:" << std::setw(20) << net_own
                      << std::string(11, ' ') << "(total stake delegated from account to self)" << std::endl
                      << indent << "delegated:" << std::setw(17) << net_others
                      << std::string(11, ' ') << "(total staked delegated to account from others)" << std::endl;
         }
         else {
            auto net_others = net_total;
            sout << indent << "delegated:" << std::setw(17) << net_others
                      << std::string(11, ' ') << "(total staked delegated to account from others)" << std::endl;
         }
      }


      auto to_pretty_time = []( int64_t nmicro, uint8_t width_for_units = 5 ) {
         if(nmicro == -1) {
             // special case. Treat it as unlimited
             return std::string("unlimited");
         }
         string unit = "us";
         double micro = static_cast<double>(nmicro);

         if( micro > 1000000*60*60ll ) {
            micro /= 1000000*60*60ll;
            unit = "hr";
         }
         else if( micro > 1000000*60 ) {
            micro /= 1000000*60;
            unit = "min";
         }
         else if( micro > 1000000 ) {
            micro /= 1000000;
            unit = "sec";
         }
         else if( micro > 1000 ) {
            micro /= 1000;
            unit = "ms";
         }
         std::stringstream ss;
         ss << setprecision(4);
         ss << micro << " ";
         if( width_for_units > 0 )
            ss << std::left << setw( width_for_units );
         ss << unit;
         return ss.str();
      };

      sout << std::fixed << setprecision(3);
      sout << indent << std::left << std::setw(11) << "used:" << std::right << std::setw(18);
      if( res.net_limit.current_used ) {
         sout << to_pretty_net(*res.net_limit.current_used) << "\n";
      } else {
         sout << to_pretty_net(res.net_limit.used) << "    ( out of date )\n";
      }
      sout << indent << std::left << std::setw(11) << "available:" << std::right << std::setw(18) << to_pretty_net( res.net_limit.available ) << "\n";
      sout << indent << std::left << std::setw(11) << "limit:"     << std::right << std::setw(18) << to_pretty_net( res.net_limit.max ) << "\n";
      sout << std::endl;

      sout << "cpu bandwidth:" << std::endl;

      if ( res.total_resources.is_object() ) {
         auto cpu_total = to_asset(res.total_resources.get_object()["cpu_weight"].as_string());

         if( res.self_delegated_bandwidth.is_object() ) {
            asset cpu_own = asset::from_string( res.self_delegated_bandwidth.get_object()["cpu_weight"].as_string() );
            staked += cpu_own;

            auto cpu_others = cpu_total - cpu_own;

            sout << indent << "staked:" << std::setw(20) << cpu_own
                      << std::string(11, ' ') << "(total stake delegated from account to self)" << std::endl
                      << indent << "delegated:" << std::setw(17) << cpu_others
                      << std::string(11, ' ') << "(total staked delegated to account from others)" << std::endl;
         } else {
            auto cpu_others = cpu_total;
            sout << indent << "delegated:" << std::setw(17) << cpu_others
                      << std::string(11, ' ') << "(total staked delegated to account from others)" << std::endl;
         }
      }

      sout << std::fixed << setprecision(3);
      sout << indent << std::left << std::setw(11) << "used:" << std::right << std::setw(18);
      if( res.cpu_limit.current_used ) {
         sout << to_pretty_time(*res.cpu_limit.current_used) << "\n";
      } else {
         sout << to_pretty_time(res.cpu_limit.used) << "    ( out of date )\n";
      }
      sout << indent << std::left << std::setw(11) << "available:" << std::right << std::setw(18) << to_pretty_time( res.cpu_limit.available ) << "\n";
      sout << indent << std::left << std::setw(11) << "limit:"     << std::right << std::setw(18) << to_pretty_time( res.cpu_limit.max ) << "\n";
      sout << std::endl;

      if( res.refund_request.is_object() ) {
         auto obj = res.refund_request.get_object();
         auto request_time = fc::time_point_sec::from_iso_string( obj["request_time"].as_string() );
         fc::time_point refund_time = request_time + fc::days(3);
         auto now = res.head_block_time;
         asset net = asset::from_string( obj["net_amount"].as_string() );
         asset cpu = asset::from_string( obj["cpu_amount"].as_string() );
         unstaking = net + cpu;

         if( unstaking > asset( 0, unstaking.get_symbol() ) ) {
            sout << std::fixed << setprecision(3);
            sout << "unstaking tokens:" << std::endl;
            sout << indent << std::left << std::setw(25) << "time of unstake request:" << std::right << std::setw(20) << string(request_time);
            if( now >= refund_time ) {
               sout << " (available to claim now with 'eosio::refund' action)\n";
            } else {
               sout << " (funds will be available in " << to_pretty_time( (refund_time - now).count(), 0 ) << ")\n";
            }
            sout << indent << std::left << std::setw(25) << "from net bandwidth:" << std::right << std::setw(18) << net << std::endl;
            sout << indent << std::left << std::setw(25) << "from cpu bandwidth:" << std::right << std::setw(18) << cpu << std::endl;
            sout << indent << std::left << std::setw(25) << "total:" << std::right << std::setw(18) << unstaking << std::endl;
            sout << std::endl;
         }
      }

      if( res.core_liquid_balance.valid() ) {
         sout << res.core_liquid_balance->get_symbol().name() << " balances: " << std::endl;
         sout << indent << std::left << std::setw(11)
                   << "liquid:" << std::right << std::setw(18) << *res.core_liquid_balance << std::endl;
         sout << indent << std::left << std::setw(11)
                   << "staked:" << std::right << std::setw(18) << staked << std::endl;
         sout << indent << std::left << std::setw(11)
                   << "unstaking:" << std::right << std::setw(18) << unstaking << std::endl;
         sout << indent << std::left << std::setw(11) << "total:" << std::right << std::setw(18) << (*res.core_liquid_balance + staked + unstaking) << std::endl;
         sout << std::endl;
      }

      if( res.rex_info.is_object() ) {
         auto& obj = res.rex_info.get_object();
         asset vote_stake = asset::from_string( obj["vote_stake"].as_string() );
         asset rex_balance = asset::from_string( obj["rex_balance"].as_string() );
         sout << rex_balance.get_symbol().name() << " balances: " << std::endl;
         sout << indent << std::left << std::setw(11)
                   << "balance:" << std::right << std::setw(18) << rex_balance << std::endl;
         sout << indent << std::left << std::setw(11)
                   << "staked:" << std::right << std::setw(18) << vote_stake << std::endl;
         sout << std::endl;
      }

      if ( res.voter_info.is_object() ) {
         auto& obj = res.voter_info.get_object();
         string proxy = obj["proxy"].as_string();
         if ( proxy.empty() ) {
            auto& prods = obj["producers"].get_array();
            sout << "producers:";
            if ( !prods.empty() ) {
               for ( size_t i = 0; i < prods.size(); ++i ) {
                  if ( i%3 == 0 ) {
                     sout << std::endl << indent;
                  }
                  sout << std::setw(16) << std::left << prods[i].as_string();
               }
               sout << std::endl;
            } else {
               sout << indent << "<not voted>" << std::endl;
            }
         } else {
            sout << "proxy:" << indent << proxy << std::endl;
         }
      }
      sout << std::endl;
   } else {
      sout << fc::json::to_pretty_string(json) << std::endl;
   }
   return sout.str();
}





////////////////////////////////////////////////////////////////
//functions to be exposed to the user
////////////////////////////////////////////////////////////////
#include "libeos.h"

std::string eosc_push_action(
string contract_account,
string action,
string data,
vector<string> permissions, 
std::vector<string> signing_key_strs,
std::vector<string> private_sign_key_strs
){
      try{
         std::vector<public_key_type> signing_keys;
         for(auto s:signing_key_strs)signing_keys.emplace_back(s);

         std::vector<private_key_type> private_sign_keys;
         for(auto s:private_sign_key_strs)private_sign_keys.emplace_back(s);

         fc::variant action_args_var;
         if( !data.empty() ) {
            action_args_var = json_from_file_or_string(data, fc::json::parse_type::relaxed_parser);
         }
         auto accountPermissions = get_account_permissions(permissions);
         auto bs = variant_to_bin( name(contract_account), name(action), action_args_var );
         return send_actions({chain::action{accountPermissions, name(contract_account), name(action), bs}}, signing_keys,packed_transaction::compression_type::none, private_sign_keys);

      }catch(...){
      return "{\"error\":\""+std::string("exception")+"\"}";
   }

}


void eosc_push_transaction(
    std::vector<eosc_action> actions,
    std::vector<std::string> signing_key_strs
){

    try{

      std::vector<public_key_type> signing_keys;
      for(auto s:signing_key_strs)signing_keys.emplace_back(s);

      std::vector<chain::action> action_list;
      for(auto& tp: actions){
         fc::variant action_args_var;
         if( !tp.data.empty() ) {
               action_args_var = json_from_file_or_string(tp.data, fc::json::parse_type::relaxed_parser);
         }

         auto accountPermissions = get_account_permissions(tp.permissions);
         auto bs = variant_to_bin( name(tp.contract_account), name(tp.action), action_args_var );
         action_list.emplace_back(accountPermissions,name(tp.contract_account),name(tp.action),bs);
      }

      send_actions(std::move(action_list), signing_keys);
    }catch(...){
      return;
   }
}



std::string eosc_get_block(
    string blockArg,
    bool get_bhs,
    bool get_binfo
){
    try{
      EOSC_ASSERT( !(get_bhs && get_binfo), "ERROR: Either --header-state or --info can be set" );
      if (get_binfo) {
         fc::optional<int64_t> block_num;
         try {
         block_num = fc::to_int64(blockArg);
         } catch (...) {
         // error is handled in assertion below
         }
         EOSC_ASSERT( block_num.valid() && (*block_num > 0), "Invalid block num: ${block_num}", ("block_num", blockArg) );
         const auto arg = fc::variant_object("block_num", static_cast<uint32_t>(*block_num));
         return fc::json::to_pretty_string(call(get_block_info_func, arg));
      } else {
         const auto arg = fc::variant_object("block_num_or_id", blockArg);
         if (get_bhs) {
         return fc::json::to_pretty_string(call(get_block_header_state_func, arg));
         } else {
         return fc::json::to_pretty_string(call(get_block_func, arg));
         }
      }
   }catch(...){
      return "{\"error\":\""+std::string("cpp exception")+"\"}";
   }
}



std::string eosc_get_info(){
    try{
      auto result = get_info();
      return fc::json::to_pretty_string(result);
    }catch(...){
      return "{\"error\":\""+std::string("cpp exception")+"\"}";
   }
}


void eosc_unlock_wallet(const std::string& wallet_name,const std::string& wallet_pw){
      fc::variants vs = {fc::variant(wallet_name), fc::variant(wallet_pw)};
      try{
         call(wallet_url, wallet_unlock, vs);
         std::cout << localized("Unlocked: ${wallet_name}", ("wallet_name", wallet_name)) << std::endl;
      }catch(...){
         return;
      }
   
}


std::string eosc_get_account(
   std::string accountName,
   std::string coresym,
   bool print_json){
   try{
      return get_account(accountName, coresym, print_json);
   }catch(...){
      return "{\"error\":\""+std::string("cpp exception")+"\"}";
   }

}


std::string eosc_get_table_rows(
   string scope,
   string code,
   string table,
   string lower,
   string upper,
   string table_key,
   string key_type,
   string index_position,
   string encode_type,
   bool binary,
   uint32_t limit,
   bool reverse,
   bool show_payer
)
{
   try{

   auto result = call(get_table_func, fc::mutable_variant_object("json", !binary)
                        ("code",code)
                        ("scope",scope)
                        ("table",table)
                        ("table_key",table_key) // not used
                        ("lower_bound",lower)
                        ("upper_bound",upper)
                        ("limit",limit)
                        ("key_type",key_type)
                        ("index_position", index_position)
                        ("encode_type", encode_type)
                        ("reverse", reverse)
                        ("show_payer", show_payer)
                        );

      std::stringstream ss;
      ss << fc::json::to_pretty_string(result) << std::endl;
      return ss.str();
   }catch(...){
      return "{\"error\":\""+std::string("cpp exception")+"\"}";
   }
}



std::string eosc_get_balance(
   std::string code,
   std::string accountName,
   std::string symbol,
   bool format_json
){
   try{
      auto result = call(get_currency_balance_func, fc::mutable_variant_object
            ("account", accountName)
            ("code", code)
            ("symbol", symbol.empty() ? fc::variant() : symbol)
            );
      std::stringstream ss;
      if (!format_json) {
         const auto& rows = result.get_array();
         for( const auto& r : rows ) {
            ss << r.as_string()
                     << std::endl;
         }
      } else {
         ss << fc::json::to_pretty_string(result) << std::endl;
      }
      return ss.str();
   }catch(...){
      return "{\"error\":\""+std::string("cpp exception")+"\"}";
   }
}



std::string eosc_get_abi(std::string accountName){
   try{
      const auto raw_abi_result = call(get_raw_abi_func, fc::mutable_variant_object("account_name", accountName));
      const auto raw_abi_blob = raw_abi_result["abi"].as_blob().data;
      if (raw_abi_blob.size() != 0) {
          const auto abi = fc::json::to_pretty_string(fc::raw::unpack<abi_def>(raw_abi_blob));
              std::stringstream ss;
              ss << abi << "\n";
              return ss.str();
          
      } else {
        FC_THROW_EXCEPTION(key_not_found_exception, "Key ${key}", ("key", "abi"));
      }
   }catch(...){
      return "{\"error\":\""+std::string("cpp exception")+"\"}";
   }
}



std::string eosc_get_scope(
   string code,
   string table,
   string lower,
   string upper,
   uint32_t limit,
   bool reverse
)
{
   try{
      auto result = call(get_table_by_scope_func, fc::mutable_variant_object("code",code)
                         ("table",table)
                         ("lower_bound",lower)
                         ("upper_bound",upper)
                         ("limit",limit)
                         ("reverse", reverse)
                         );

      std::stringstream ss;
      ss << fc::json::to_pretty_string(result) << std::endl;
      return ss.str();
   }catch(...){
      return "{\"error\":\""+std::string("cpp exception")+"\"}";
   }
}



void eosc_init(eosc_config config){


    //set up configs
    url = config.url;
    wallet_url = config.wallet_url; //to be set to default_wallet_url in main
    no_verify = config.no_verify;
    tx_ref_block_num_or_id = config.tx_ref_block_num_or_id;
    tx_force_unique = config.tx_force_unique;
    tx_dont_broadcast = config.tx_dont_broadcast;
    tx_return_packed = config.tx_return_packed;
    tx_skip_sign = config.tx_skip_sign;
    tx_print_json = config.tx_print_json;
    tx_use_old_rpc = config.tx_use_old_rpc;
    tx_json_save_file = config.tx_json_save_file;
    print_request = config.print_request;
    print_response = config.print_response;
    no_auto_keosd = config.no_auto_keosd;
    verbose = config.verbose;
    tx_max_cpu_usage = config.tx_max_cpu_usage;
    tx_max_net_usage = config.tx_max_net_usage;
    delaysec = config.delaysec;

    //init http context
    context = eosio::client::http::create_http_context();
    wallet_url = default_wallet_url;
}
