fun setActions(actions: Outlist): void asm "c5 POP";
fun builder.storeZeroes(mutate self, x: int): self asm "STZEROES";
fun acceptExternalMessage(): void asm "ACCEPT"; 
fun slice.loadTwoSlices( self, len: int): (slice, slice) asm "LDSLICEX";

const INVALID_SIGNATURE: int= 33;
const INVALID_SUBWALLET_ID: int = 34;
const INVALID_CREATED_AT: int = 35;
const ALREADY_EXECUTED: int = 36;
const INVALID_MESSAGE_TO_SEND: int= 37;
const INVALID_TIMEOUT: int= 38;

const CELL_BIT_SIZE: int = 1023;
const BIT_NUMBER_SIZE: int = 10; // 2^10 = 1024

struct (0b0) None

struct (0b1) Value<X> {
    value: X
}

type Maybe<X> = Value<X> | None

type Either<X, Y> = EitherLeft<X> | EitherRight<Y>

struct (0b0) EitherLeft<X> {
    value: X
}
struct (0b1) EitherRight<X> {
    value: X
}

struct (0b0) InternalMessage {
    ihrDisabled: bool
    bounce: bool
    bounced: bool
    src: any_address
    dest: address
    value: CurrencyCollection
    extraFlags: varuint16
    forwardFee: coins
    createdLT: uint64
    createdAt: uint32
}

struct (0b10) ExternalInMessageInfo {
    src: any_address
    dest: address
    importFee: coins
}

struct (0b11) ExternalOutMessageInfo {
    src: address
    dest: any_address
    createdLt: uint64
    createdAt: uint32
}

type CommonMessageInfo =
    | InternalMessage
    | ExternalInMessageInfo
    | ExternalOutMessageInfo

/// Represents a currency collection as TON amount + extra currencies.
struct CurrencyCollection {
    /// Amount in nanoton.
    grams: coins
    /// Extra currencies.
    other: map<int32, varuint32>
}

struct Message<TBody = RemainingBitsAndRefs, TInfo = CommonMessageInfo> {
    info: TInfo
    init: Maybe<Either<StateInit, Cell<StateInit>>>
    body: Either<TBody, Cell<TBody>>
}

type Outlist = cell;

struct (0xae42e5a4) InternalTransfer {
    queryId: uint64;
    actions: Cell<Outlist>;
}

struct ExternalInMsgBody {
   body: Cell<MsgInner>;
}   

struct WalletStorage {
    publicKey: uint256;
    subwalletId: uint32;
    oldQueries: map<uint13, cell>;
    queries: map<uint13, cell>;
    lastCleanTime: int64;
    timeout: int22;
}

fun WalletStorage.save(self) {
    contract.setData(self.toCell());
}

fun WalletStorage.load() {
    return WalletStorage.fromCell(contract.getData());  
}

struct MsgInner {
    subwalletId: uint32;
    messageToSend: cell;
    sendMode: uint8;
    shift: uint13;
    bitNumber: uint10;
    createdAt: uint64;
    timeout: uint22;
}


type AllowedExternalMessageToWallet = ExternalInMsgBody;
type AllowedInternalMessageToWallet = InternalTransfer;


fun onInternalMessage(in: InMessage) {
    val msg = lazy AllowedInternalMessageToWallet.fromSlice(in.body);
    match (msg) {
        InternalTransfer => {

            if (in.senderAddress != contract.getAddress()) {
                return();
            }

            setActions(msg.actions);
            contract.setCodePostponed(contract.getCode());
            return();
        }
         
        else => {
            return();
        } 
    }
}


fun onExternalMessage(inMsg: slice) {

    var signature = inMsg.getLastBits(512);  
    var storage = WalletStorage.load();

    if (storage.lastCleanTime < (blockchain.now() - storage.timeout)) {
        (storage.oldQueries, storage.queries) = (storage.queries, createEmptyMap<uint13, cell>());
        if (storage.lastCleanTime < (blockchain.now() - (storage.timeout * 2))) {
            storage.oldQueries = createEmptyMap();
        }
        storage.lastCleanTime = blockchain.now();
    }
    
    var msg = lazy AllowedExternalMessageToWallet.fromSlice(inMsg);
    val msgInnerHash = msg.body.hash();

    assert(isSignatureValid(msgInnerHash, signature, storage.publicKey)) throw INVALID_SIGNATURE;

    var innerSlice = lazy MsgInner.fromCell(msg.body);

    assert(innerSlice.subwalletId == storage.subwalletId) throw INVALID_SUBWALLET_ID;
    assert(innerSlice.timeout == storage.timeout) throw INVALID_TIMEOUT;
    assert(innerSlice.createdAt > blockchain.now() - storage.timeout) throw INVALID_CREATED_AT;
    assert(innerSlice.createdAt <= blockchain.now()) throw INVALID_CREATED_AT;

    var resOld = storage.oldQueries.get(innerSlice.shift);
    if (resOld.isFound) {
        var value = resOld.loadValue().beginParse();
        value.skipBits(innerSlice.bitNumber);
        assert(!value.preloadInt(1)) throw ALREADY_EXECUTED;
    }

    var res = storage.queries.get(innerSlice.shift);

    var newValue: builder;
    
    if (res.isFound) {
        var (tail, head) = res.loadValue().beginParse().loadTwoSlices(innerSlice.bitNumber);
        assert(head.loadInt(1) == 0) throw ALREADY_EXECUTED;
        newValue = beginCell().storeSlice(tail).storeBool(true).storeSlice(head);
    } else {
        newValue = beginCell().storeZeroes(innerSlice.bitNumber).storeBool(true).storeZeroes(CELL_BIT_SIZE - innerSlice.bitNumber - 1);
    }

    acceptExternalMessage();
    storage.queries.set(innerSlice.shift, newValue.endCell());
    storage.save();
    commitContractDataAndActions();
    var msgToSend = lazy Message<RemainingBitsAndRefs, CommonMessageInfo>.fromCell(innerSlice.messageToSend, { throwIfOpcodeDoesNotMatch: INVALID_MESSAGE_TO_SEND});

    if (msgToSend.init is None) {

        match (msgToSend.info) {
            ExternalInMessageInfo => { throw INVALID_MESSAGE_TO_SEND }
            ExternalOutMessageInfo => { throw INVALID_MESSAGE_TO_SEND }
            InternalMessage => { 
                if (msgToSend.info.bounced) { throw INVALID_MESSAGE_TO_SEND }
                if (!(msgToSend.info.src.isNone())) { throw INVALID_MESSAGE_TO_SEND }
                var output = OutMessage { messageCell: innerSlice.messageToSend };
                output.send(innerSlice.sendMode | SEND_MODE_IGNORE_ERRORS);
                return();
            }
        }
    } else { throw INVALID_MESSAGE_TO_SEND }
}



get fun get_public_key()  {
    var storage = lazy WalletStorage.load();
    return (storage.publicKey);
}

get fun get_subwallet_id() {
    var storage = lazy WalletStorage.load();
    return (storage.subwalletId);
}

get fun get_last_clean_time() {
    var storage = lazy WalletStorage.load();
    return (storage.lastCleanTime);
}

get fun get_timeout() {
    var storage = lazy WalletStorage.load();
    return (storage.timeout);
}

@method_id(0x1cbf2)
fun isProcessed(queryId: int, needClean: int): int {
    var shift = queryId >> BIT_NUMBER_SIZE;
    var bitNumber = queryId & CELL_BIT_SIZE;

    var storage = lazy WalletStorage.load();

    if (needClean) {
        if (storage.lastCleanTime < (blockchain.now() - storage.timeout)) {
            (storage.oldQueries, storage.queries) = (storage.queries, createEmptyMap());
            if (storage.lastCleanTime < (blockchain.now() - (storage.timeout * 2))) {
                storage.oldQueries = createEmptyMap();
            }
            storage.lastCleanTime = blockchain.now();
        }
    }
    
    storage.save();

    var resOld = storage.oldQueries.get(shift);
    if (resOld.isFound) {
        var value = resOld.loadValue().beginParse();
        value.skipBits(bitNumber);
        if (value.preloadInt(1)) {
            return -1;
        }
    }

    var res = storage.queries.get(shift);
    if (res.isFound) {
        var valueCurrent = res.loadValue().beginParse();
        valueCurrent.skipBits(bitNumber);
        if (valueCurrent.preloadInt(1)) {
            return -1;
        }
    }

    return 0;
}