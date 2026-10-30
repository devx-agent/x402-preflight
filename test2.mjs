import { checkOption } from "./src/index.js";
const t=new URL("https://a.example/x");
const cases={
 good:{scheme:"exact",network:"eip155:8453",amount:"10000",asset:"0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",payTo:"0xB3cDDccEe6B150c8efFD55B961afc0Ecefe7f247",maxTimeoutSeconds:60,extra:{name:"USD Coin",version:"2"}},
 baddomain:{scheme:"exact",network:"eip155:8453",amount:"10000",asset:"0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",payTo:"0xB3cDDccEe6B150c8efFD55B961afc0Ecefe7f247",maxTimeoutSeconds:60,extra:{name:"USDC",version:"2"}},
 badsum:{scheme:"exact",network:"eip155:8453",amount:"20000000",asset:"0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",payTo:"0xB3cDDccEe6B150c8efFD55B961afc0Ecefe7f248",maxTimeoutSeconds:10},
 testnet_v1:{scheme:"exact",network:"base-sepolia",maxAmountRequired:"1000",asset:"0x036CbD53842c5426634e7929541eC2318f3dCF7e",payTo:"0x0000000000000000000000000000000000000000",resource:"https://evil.example/x",maxTimeoutSeconds:60,extra:{name:"USDC",version:"2"}},
};
for (const [k,o] of Object.entries(cases)) { const r=await checkOption(o,0,k.includes("v1")?1:2,t,false); console.log(k,r.verdict,r.price_usdc,r.findings.map(f=>f.code).join(",")); }
