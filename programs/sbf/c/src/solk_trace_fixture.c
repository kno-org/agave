/** Local, deterministic tracing fixture. Built from kno-org/agave; never a genesis override. */
#include <solana_sdk.h>

/* Wire: u8 mode, u8 remaining self-invokes, u64 lamports (LE).
 * Modes: 0 CPI transfer; 1 nested CPI transfer; 2 transfer then deliberate rollback;
 * 3 hold real account locks using metered computation; 4 update owned counter + CPI.
 * Accounts: payer, recipient, System Program, this program, optional owned counter.
 */
uint64_t entrypoint(const uint8_t *input) {
  SolAccountInfo accounts[5];
  SolParameters p = {.ka=accounts};
  if (!sol_deserialize(input,&p,SOL_ARRAY_SIZE(accounts)) || p.data_len!=10 || p.ka_num<4) return ERROR_INVALID_ARGUMENT;
  const uint8_t mode=p.data[0];
  if (mode==3) {
    volatile uint64_t accumulator=1;
    while(sol_remaining_compute_units()>20000) {
      for(uint64_t i=0;i<64;i++) accumulator=(accumulator*33)^i;
    }
    sol_set_return_data((const uint8_t *)&accumulator,8);
    return SUCCESS;
  }
  if(mode==4) {
    if(p.ka_num!=5 || accounts[4].data_len!=8 || !SolPubkey_same(accounts[4].owner,p.program_id) || !accounts[4].is_writable) return ERROR_INVALID_ARGUMENT;
    uint64_t counter=0;for(uint64_t i=0;i<8;i++)counter|=((uint64_t)accounts[4].data[i])<<(8*i);
    counter++;for(uint64_t i=0;i<8;i++)accounts[4].data[i]=(uint8_t)(counter>>(8*i));
  }
  if(mode==1 && p.data[1]>0) {
    uint8_t data[10];for(uint64_t i=0;i<10;i++)data[i]=p.data[i];data[1]--;
    SolAccountMeta metas[]={{accounts[0].key,true,true},{accounts[1].key,true,false},{accounts[2].key,false,false},{accounts[3].key,false,false}};
    SolPubkey program_id=*p.program_id;
    SolInstruction child={&program_id,metas,4,data,10};
    return sol_invoke(&child,accounts,p.ka_num);
  }
  uint8_t data[12]={2,0,0,0};for(uint64_t i=0;i<8;i++)data[4+i]=p.data[2+i];
  SolAccountMeta metas[]={{accounts[0].key,true,true},{accounts[1].key,true,false}};
  SolInstruction transfer={accounts[2].key,metas,2,data,12};
  const uint64_t result=sol_invoke(&transfer,accounts,p.ka_num);
  if(result!=SUCCESS)return result;
  sol_set_return_data(p.data+2,8);
  return mode==2 ? 42 : SUCCESS;
}
