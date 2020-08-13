#pragma once
#include <string>
#include <vector>


/*
* eosc library config
*     - url: target blockchain rpc endpoint
*     - wallet_url: wallet url used for sign transaction
*     - tx_print_json: print out transaction in json format to stdout
*     - print_request: print request body to stdout
*     - print_response: print response body to stdout
*     - verbose: output smart contract print to stdout
*/
struct eosc_config{
   std::string       url = "http://127.0.0.1:8888/";
   std::string       wallet_url; //to be set to default_wallet_url in main
   bool              no_verify = false;
   std::string       tx_ref_block_num_or_id;
   bool              tx_force_unique = false;
   bool              tx_dont_broadcast = false;
   bool              tx_return_packed = false;
   bool              tx_skip_sign = false;
   bool              tx_print_json = false;
   bool              tx_use_old_rpc = false;
   std::string       tx_json_save_file;
   bool              print_request = false;
   bool              print_response = false;
   bool              no_auto_keosd = false;
   bool              verbose = false;
   uint8_t           tx_max_cpu_usage = 0;
   uint32_t          tx_max_net_usage = 0;
   uint32_t          delaysec = 0;
};

/*
* init eosc context, always need to be called before use any other functions
* arguments:
*     - config: config struct defined above. 
*/
void eosc_init(eosc_config config = {});

/*
* get basic blockchain information
* arguments:
* return:
*    - json string contains basic blockchain information
*/
std::string eosc_get_info();

/*
* push single action transaction to blockchain
* arguments:
*    - contract_account: target smart contract name
*    - action: action name
*    - data: json string type action arguments
*    - permission: permission level for the transaction 
*/
std::string eosc_push_action(
   std::string contract_account,
   std::string action,
   std::string data,
   std::vector<std::string> permissions, 
   std::vector<std::string> signing_key_strs = {}, 
   std::vector<std::string> private_sign_key_strs = {}
);


/*
* single action define
* arguments:
*    - contract_account: target smart contract name
*    - action: action name
*    - data: json string type action arguments
*    - permission: permission level for the transaction 
*/
struct eosc_action{
   std::string contract_account;
   std::string action;
   std::string data;
   std::vector<std::string> permissions;
};
void eosc_push_transaction(
   std::vector<eosc_action> actions,
   std::vector<std::string> signing_key_strs = {}
);



/*
* get target block info
* arguments:
*    - blockArg:  The number or ID of the block to retrieve
*    - get_binfo: get block information
*    - get_bhs:  Get block header state from fork database instead
*/
std::string eosc_get_block(
    std::string blockArg,
    bool get_bhs = false,
    bool get_binfo = false
);


/*
* unlock wallet
* arguments:
*    - wallet_name:  name of the wallet
*    - wallet_pw: password of the wallet
*/
void eosc_unlock_wallet(
   const std::string& wallet_name, 
   const std::string& wallet_pw
);

/*
* get account details
* arguments:
*    - accountName:  name of the account
*    - coresym: expected core symbol default empty
*    - print_json: output json string default true
*/
std::string eosc_get_account(
   std::string accountName,
   std::string coresym = "",
   bool print_json = true
);



/*
* get table rows
* arguments:
*   string scope,
*   string code,
*   string table,
*   string lower,
*   string upper,
*   string table_key,
*   string key_type,
*   string index_position,
*   string encode_type = "dec",
*   bool binary = false,
*   uint32_t limit = 10,
*   bool reverse = false,
*   bool show_payer = false
*/
std::string eosc_get_table_rows(
   std::string scope,
   std::string code,
   std::string table,
   std::string lower,
   std::string upper,
   std::string table_key,
   std::string key_type,
   std::string index_position,
   std::string encode_type = "dec",
   bool binary = false,
   uint32_t limit = 10,
   bool reverse = false,
   bool show_payer = false
);


/*
* get currency balance
* arguments:
*    - code: account issues currency
*    - accountName:  name of the account
*    - symbol: currency symbol
*    - format_json: output json string default true
*/
std::string eosc_get_balance(
   std::string code,
   std::string accountName,
   std::string symbol,
   bool format_json = false
);

/*
* get abi
* arguments: 
*  - accountName: account which holds abi
*/
std::string eosc_get_abi(
   std::string accountName
);


/*
* get scope
* arguments: 
*  - table: table name
*  - lower: lower bound
*  - uppder: upper bound
*/
std::string eosc_get_scope(
   std::string code,
   std::string table,
   std::string lower,
   std::string upper,
   uint32_t limit = 100,
   bool reverse = false
);