const te=new TextEncoder(),td=new TextDecoder();
export const B64={enc:a=>btoa(String.fromCharCode(...a)),dec:s=>Uint8Array.from(atob(s),c=>c.charCodeAt(0))};
const DB='caja-secure-v3',STORE='encrypted';
export async function db(){return new Promise((ok,no)=>{const r=indexedDB.open(DB,1);r.onupgradeneeded=()=>r.result.createObjectStore(STORE);r.onsuccess=()=>ok(r.result);r.onerror=()=>no(r.error)})}
export async function getSecure(k){const d=await db();return new Promise((ok,no)=>{const r=d.transaction(STORE).objectStore(STORE).get(k);r.onsuccess=()=>ok(r.result??null);r.onerror=()=>no(r.error)})}
export async function putSecure(k,v){const d=await db();return new Promise((ok,no)=>{const t=d.transaction(STORE,'readwrite');t.objectStore(STORE).put(v,k);t.oncomplete=()=>ok();t.onerror=()=>no(t.error)})}
export async function delSecure(k){const d=await db();return new Promise((ok,no)=>{const t=d.transaction(STORE,'readwrite');t.objectStore(STORE).delete(k);t.oncomplete=()=>ok();t.onerror=()=>no(t.error)})}
export async function deriveKEK(secret,salt,iterations=600000){const base=await crypto.subtle.importKey('raw',te.encode(secret),'PBKDF2',false,['deriveKey']);return crypto.subtle.deriveKey({name:'PBKDF2',salt,iterations,hash:'SHA-256'},base,{name:'AES-GCM',length:256},false,['encrypt','decrypt'])}
export async function sealJSON(value,key,aad){const iv=crypto.getRandomValues(new Uint8Array(12));const ct=await crypto.subtle.encrypt({name:'AES-GCM',iv,additionalData:te.encode(aad)},key,te.encode(JSON.stringify(value)));return{v:3,alg:'A256GCM',aad,iv:B64.enc(iv),ct:B64.enc(new Uint8Array(ct))}}
export async function openJSON(blob,key,aad){if(blob.v!==3||blob.aad!==aad)throw Error('envelope');const pt=await crypto.subtle.decrypt({name:'AES-GCM',iv:B64.dec(blob.iv),additionalData:te.encode(aad)},key,B64.dec(blob.ct));return JSON.parse(td.decode(pt))}
export async function newVaultKey(){return crypto.subtle.generateKey({name:'AES-GCM',length:256},true,['encrypt','decrypt'])}
export async function exportKey(k){return new Uint8Array(await crypto.subtle.exportKey('raw',k))}
export async function importKey(raw){return crypto.subtle.importKey('raw',raw,{name:'AES-GCM'},true,['encrypt','decrypt'])}
export async function wrapKey(vk,kek,vaultId){return sealJSON({key:B64.enc(await exportKey(vk))},kek,'caja:v3:'+vaultId+':wrapped-vault-key')}
export async function unwrapKey(blob,kek,vaultId){const x=await openJSON(blob,kek,'caja:v3:'+vaultId+':wrapped-vault-key');return importKey(B64.dec(x.key))}
export function randomId(bytes=18){const a=crypto.getRandomValues(new Uint8Array(bytes));return B64.enc(a).replaceAll('+','-').replaceAll('/','_').replaceAll('=','')}
export function recoveryCode(){return randomId(24).match(/.{1,6}/g).join('-')}
export async function encryptBytes(bytes,key,aad){const iv=crypto.getRandomValues(new Uint8Array(12));const ct=await crypto.subtle.encrypt({name:'AES-GCM',iv,additionalData:te.encode(aad)},key,bytes);const head=te.encode(JSON.stringify({v:3,alg:'A256GCM',aad,iv:B64.enc(iv)})+'\n');const out=new Uint8Array(head.length+ct.byteLength);out.set(head);out.set(new Uint8Array(ct),head.length);return out}
export async function decryptBytes(bytes,key,aad){const nl=bytes.indexOf(10),h=JSON.parse(td.decode(bytes.slice(0,nl)));if(h.v!==3||h.aad!==aad)throw Error('asset envelope');return crypto.subtle.decrypt({name:'AES-GCM',iv:B64.dec(h.iv),additionalData:te.encode(aad)},key,bytes.slice(nl+1))}

export async function legacyOpenJSON(blob,key){const pt=await crypto.subtle.decrypt({name:'AES-GCM',iv:B64.dec(blob.iv)},key,B64.dec(blob.ct));return JSON.parse(td.decode(pt))}
export async function legacyUnwrapKey(blob,kek){const x=await legacyOpenJSON(blob,kek);return importKey(B64.dec(x.k))}
