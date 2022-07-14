// Copyright (c) 2012-2022 The Elastos Open Source Project
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

import { Buffer } from "buffer";
import { ByteStream } from "../../common/bytestream";
import { Error, ErrorChecker } from "../../common/ErrorChecker";
import { Log } from "../../common/Log";
import { size_t, uint8_t } from "../../types";
import { Base58 } from "../../walletcore/base58";
import { BASE64 } from "../../walletcore/base64";
import { EcdsaSigner } from "../../walletcore/ecdsasigner";
import { Payload } from "./Payload";

export const DID_DEFAULT_TYPE = "ECDSAsecp256r1";
export const PREFIX_DID = "did:elastos:";
export const UPDATE_DID = "update";
export const PRIMARY_KEY = "#primary";

type DIDPubKeyInfoArray = DIDPubKeyInfo[];
type CredentialSubjectArray = CredentialSubject[];
type ServiceEndpoints = ServiceEndpoint[];
type VerifiableCredentialArray = VerifiableCredential[];

export type DIDHeaderInfoJson = {
  specification: string;
  operation: string;
  previousTxid?: string;
};

export type DIDPubKeyInfoJson = {
  id?: string;
  publicKeyBase58?: string;
  type?: string;
  controller?: string;
};

export type DIDProofInfoJson = {
  type?: string;
  verificationMethod: string;
  signature: string;
};

export type CredentialSubjectJson = { id?: string };

export type VerifiableCredentialJson = {
  id?: string;
  type?: string[];
  issuer: string;
  issuanceDate: string;
  expirationDate: string;
  credentialSubject?: CredentialSubjectJson;
  proof?: DIDProofInfoJson;
};

export type ServiceEndpointJson = {
  id?: string;
  type?: string;
  serviceEndpoint?: string;
};

export type DIDPayloadProofJson = {
  type?: string;
  created?: string;
  creator?: string;
  signatureValue: string;
};

export type DIDPayloadInfoJson = {
  controller?: string[] | string;
  id: string;
  publicKey: DIDPubKeyInfoJson[];
  authentication: DIDPubKeyInfoJson[];
  authorization: DIDPubKeyInfoJson[];
  expires: string;
  verifiableCredential: VerifiableCredentialJson[];
  service: ServiceEndpointJson[];
  proof: DIDPayloadProofJson;
};

export type DIDInfoJson = {
  header: DIDHeaderInfoJson;
  payload: string;
  proof: DIDProofInfoJson;
};

export class DIDHeaderInfo {
  private _specification: string;
  private _operation: string;
  private _previousTxid: string;

  static newFromParams(specification: string, operation: string, preTxID = "") {
    let headerInfo = new DIDHeaderInfo();
    headerInfo._specification = specification;
    headerInfo._operation = operation;
    headerInfo._previousTxid = preTxID;
    return headerInfo;
  }

  specification(): string {
    return this._specification;
  }

  setSpecification(specification: string) {
    this._specification = specification;
  }

  operation(): string {
    return this._operation;
  }

  setOperation(operation: string) {
    this._operation = operation;
  }

  setPreviousTxid(txid: string) {
    this._previousTxid = txid;
  }

  previousTxid(): string {
    return this._previousTxid;
  }

  estimateSize(version: uint8_t): size_t {
    let stream = new ByteStream();
    let size: size_t = 0;

    size = stream.writeVarUInt(this._specification.length);
    size += this._specification.length;
    size += stream.writeVarUInt(this._operation.length);
    size += this._operation.length;

    if (this._operation == UPDATE_DID) {
      size += stream.writeVarUInt(this._previousTxid.length);
      size += this._previousTxid.length;
    }

    return size;
  }

  serialize(stream: ByteStream, version: uint8_t) {
    stream.writeVarString(this._specification);
    stream.writeVarString(this._operation);
    if (this._operation == UPDATE_DID) {
      stream.writeVarString(this._previousTxid);
    }
  }

  deserialize(stream: ByteStream, version: uint8_t): boolean {
    this._specification = stream.readVarString();
    if (!this._specification) {
      Log.error("DIDHeaderInfo deserialize: specification");
      return false;
    }
    this._operation = stream.readVarString();
    if (!this._operation) {
      Log.error("DIDHeaderInfo deserialize: operation");
      return false;
    }

    if (this._operation == UPDATE_DID) {
      this._previousTxid = stream.readVarString();
      if (!this._previousTxid) {
        Log.error("DIDHeaderInfo deserialize: previousTxid");
        return false;
      }
    }

    return true;
  }

  toJson(version: uint8_t): DIDHeaderInfoJson {
    let j = <DIDHeaderInfoJson>{};
    j["specification"] = this._specification;
    j["operation"] = this._operation;
    if (this._operation == UPDATE_DID) {
      j["previousTxid"] = this._previousTxid;
    }
    return j;
  }

  fromJson(j: DIDHeaderInfoJson, version: uint8_t) {
    this._specification = j["specification"];
    this._operation = j["operation"];

    if (this._operation == UPDATE_DID) {
      this._previousTxid = j["previousTxid"];
    }
  }

  equals(info: DIDHeaderInfo): boolean {
    return (
      this._specification == info._specification &&
      this._operation == info._operation &&
      this._previousTxid == info._previousTxid
    );
  }
}

export class DIDPubKeyInfo {
  private _id: string;
  private _type: string;
  private _controller: string;
  private _publicKeyBase58: string;

  public static newFromParams(
    id: string,
    pubkeyBase58: string,
    controller: string,
    type: string
  ) {
    const info = new DIDPubKeyInfo();
    info._id = id;
    info._publicKeyBase58 = pubkeyBase58;
    info._controller = controller;
    info._type = type;
    return info;
  }

  id(): string {
    return this._id;
  }

  setID(id: string) {
    this._id = id;
  }

  type(): string {
    return this._type;
  }

  setType(type: string) {
    this._type = type;
  }

  controller(): string {
    return this._controller;
  }

  setController(controller: string) {
    this._controller = controller;
  }

  publicKeyBase58(): string {
    return this._publicKeyBase58;
  }

  setPublicKeyBase58(pubkey: string) {
    this._publicKeyBase58 = pubkey;
  }

  autoFill(did: string) {
    if (this._id[0] == "#") {
      this._id = did + this._id;
    }

    if (!this._controller && !this._publicKeyBase58) {
      this._controller = did;
    }
  }
  /*
    toOrderedJson(JsonGenerator *generator) const {
      JsonGenerator_WriteStartObject(generator);

      JsonGenerator_WriteFieldName(generator, "id");
      JsonGenerator_WriteString(generator, _id.c_str());

      JsonGenerator_WriteFieldName(generator, "type");
      JsonGenerator_WriteString(generator, _type.c_str());

      JsonGenerator_WriteFieldName(generator, "controller");
      JsonGenerator_WriteString(generator, _controller.c_str());

      JsonGenerator_WriteFieldName(generator, "publicKeyBase58");
      JsonGenerator_WriteString(generator, _publicKeyBase58.c_str());

      JsonGenerator_WriteEndObject(generator);
    }
    */

  toJson(version: uint8_t): DIDPubKeyInfoJson {
    let j = <DIDPubKeyInfoJson>{};

    j["id"] = this._id;
    j["type"] = this._type;

    if (!this._controller) {
      j["controller"] = this._controller;
    }

    j["publicKeyBase58"] = this._publicKeyBase58;

    return j;
  }

  fromJson(j: DIDPubKeyInfoJson | string, version: uint8_t) {
    if (j["id"]) {
      this._id = j["id"];
      this._publicKeyBase58 = j["publicKeyBase58"];
    } else if (typeof j === "string") {
      this._id = j;
    }

    if (j["type"]) {
      this._type = j["type"];
    } else {
      this._type = DID_DEFAULT_TYPE;
    }

    if (j["controller"]) {
      this._controller = j["controller"];
      ErrorChecker.checkParam(
        !this._controller && this._controller.indexOf(PREFIX_DID) === -1,
        Error.Code.InvalidArgument,
        "invalid controller"
      );
    }
  }
}

export class CredentialSubject {
  private _id: string;
  private _properties: CredentialSubjectJson;

  setID(id: string) {
    ErrorChecker.checkParam(
      id.indexOf(PREFIX_DID) === -1,
      Error.Code.InvalidArgument,
      "invalid id"
    );
    this._id = id;
    this.addProperties("id", id);
  }

  id(): string {
    return this._id;
  }

  autoFill(did: string) {
    if (!this._id) {
      this._id = did;
    }
  }

  getProperties(): CredentialSubjectJson {
    return this._properties;
  }

  getValue(key: string) {
    ErrorChecker.checkParam(
      !this.hasProperties(key),
      Error.Code.InvalidArgument,
      "invalid key"
    );
    return this._properties[key];
  }

  hasProperties(key: string): boolean {
    return Object.keys(this._properties).includes(key);
  }

  addProperties(key: string, value: string) {
    this._properties[key] = value;
  }

  /*
    void CredentialSubject::ToOrderedJson(JsonGenerator *generator) const {
      JsonGenerator_WriteStartObject(generator);

      JsonGenerator_WriteStringField(generator, "id", _id.c_str());

      std::map<std::string, nlohmann::json> propertiesMap = _properties;
      for (auto & m : propertiesMap) {
        JsonGenerator_WriteFieldName(generator, m.first.c_str());
        Properties2OrderedJson(generator, m.second);
      }

      JsonGenerator_WriteEndObject(generator);
    }

    void CredentialSubject::Properties2OrderedJson(JsonGenerator *generator, const nlohmann::json &properties) const {
      if (properties.is_array()) {
        JsonGenerator_WriteStartArray(generator);
        for (auto & p : properties)
          Properties2OrderedJson(generator, p);
        JsonGenerator_WriteEndArray(generator);
      } else if (properties.is_object()) {
        std::map<std::string, nlohmann::json> propertiesMap = properties;
        JsonGenerator_WriteStartObject(generator);
        for (auto & m : propertiesMap) {
          JsonGenerator_WriteFieldName(generator, m.first.c_str());
          Properties2OrderedJson(generator, m.second);
        }
        JsonGenerator_WriteEndObject(generator);
      } else if (properties.is_string()) {
        JsonGenerator_WriteString(generator, properties.get<std::string>().c_str());
      } else if (properties.is_boolean()) {
        JsonGenerator_WriteBoolean(generator, properties.get<bool>());
      } else if (properties.is_number_float()) {
        JsonGenerator_WriteDouble(generator, properties.get<double>());
      } else if (properties.is_number()) {
        JsonGenerator_WriteNumber(generator, properties.get<int>());
      } else if (properties.is_null()) {
        JsonGenerator_WriteString(generator, NULL);
      } else {
        ErrorChecker::ThrowParamException(Error::InvalidArgument, "unsupport other josn value type: " + properties.dump());
      }
    }
*/
  toJson(version: uint8_t): CredentialSubjectJson {
    let j = this._properties;
    j["id"] = this._id;
    return j;
  }

  fromJson(j: CredentialSubjectJson, version: uint8_t) {
    if (j["id"]) {
      this._id = j["id"];
      ErrorChecker.checkParam(
        this._id.indexOf(PREFIX_DID) === -1,
        Error.Code.InvalidArgument,
        "invalid id"
      );
    }

    this._properties = j;
    delete this._properties.id;
  }
}

export class ServiceEndpoint {
  private _id: string;
  private _type: string;
  private _serviceEndpoint: string;

  static newFromParams(id: string, type: string, serviceEndpoint: string) {
    let endpoint = new ServiceEndpoint();
    endpoint._id = id;
    endpoint._type = type;
    endpoint._serviceEndpoint = serviceEndpoint;
    return endpoint;
  }

  setID(id: string) {
    this._id = id;
  }

  id(): string {
    return this._id;
  }

  setType(type: string) {
    this._type = type;
  }

  type(): string {
    return this._type;
  }

  setService(service: string) {
    this._serviceEndpoint = service;
  }

  getService(): string {
    return this._serviceEndpoint;
  }

  autoFill(did: string) {
    if (this._id[0] == "#") {
      this._id = did + this._id;
    }
  }

  /*
    void ServiceEndpoint::ToOrderedJson(JsonGenerator *generator) const {
      JsonGenerator_WriteStartObject(generator);

      JsonGenerator_WriteStringField(generator, "id", _id.c_str());
      JsonGenerator_WriteStringField(generator, "type", _type.c_str());
      JsonGenerator_WriteStringField(generator, "serviceEndpoint", _serviceEndpoint.c_str());

      JsonGenerator_WriteEndObject(generator);
    }
*/

  toJson(version: uint8_t): ServiceEndpointJson {
    let j = <ServiceEndpointJson>{};

    j["id"] = this._id;
    j["type"] = this._type;
    j["serviceEndpoint"] = this._serviceEndpoint;

    return j;
  }

  fromJson(j: ServiceEndpointJson, version: uint8_t) {
    if (j["id"]) this._id = j["id"];

    if (j["type"]) this._type = j["type"];

    if (j["serviceEndpoint"]) this._serviceEndpoint = j["serviceEndpoint"];
  }
}

export class VerifiableCredential {
  private _id: string;
  private _types: string[];
  private _issuer: string;
  private _issuanceDate: string;
  private _expirationDate: string;
  private _credentialSubject: CredentialSubject;
  private _proof: DIDProofInfo;

  setID(id: string) {
    this._id = id;
  }

  id() {
    return this._id;
  }

  setTypes(types: string[]) {
    this._types = types;
  }

  types(): string[] {
    return this._types;
  }

  setIssuer(issuer: string) {
    this._issuer = issuer;
  }

  getIssuer(): string {
    return this._issuer;
  }

  setIssuerDate(issuerDate: string) {
    this._issuanceDate = issuerDate;
  }

  getIssuerDate(): string {
    return this._issuanceDate;
  }

  setCredentialSubject(credentialSubject: CredentialSubject) {
    this._credentialSubject = credentialSubject;
  }

  getCredentialSubject(): CredentialSubject {
    return this._credentialSubject;
  }

  setProof(proof: DIDProofInfo) {
    this._proof = proof;
  }

  proof(): DIDProofInfo {
    return this._proof;
  }

  autoFill(did: string) {
    if (this._id[0] == "#") {
      this._id = did + this._id;
    }

    this._credentialSubject.autoFill(did);

    if (!this._issuer) {
      this._issuer = this._credentialSubject.id();
    }

    this._proof.autoFill(this._issuer);
  }

  /*
    void VerifiableCredential::ToOrderedJson(JsonGenerator *generator) const {
      JsonGenerator_WriteStartObject(generator);

      JsonGenerator_WriteFieldName(generator, "id");
      JsonGenerator_WriteString(generator, _id.c_str());

      JsonGenerator_WriteFieldName(generator, "type");
      JsonGenerator_WriteStartArray(generator);

      std::map<std::string, std::string> sortedTypes;
      for (const std::string &type : _types) {
        sortedTypes[type] = "";
      }
      for (std::map<std::string, std::string>::iterator it = sortedTypes.begin(); it != sortedTypes.end(); ++it) {
        JsonGenerator_WriteString(generator, (*it).first.c_str());
      }

      JsonGenerator_WriteEndArray(generator);

      JsonGenerator_WriteFieldName(generator, "issuer");
      JsonGenerator_WriteString(generator, _issuer.c_str());

      JsonGenerator_WriteFieldName(generator, "issuanceDate");
      JsonGenerator_WriteString(generator, _issuanceDate.c_str());

      if (!_expirationDate.empty()) {
        JsonGenerator_WriteFieldName(generator, "expirationDate");
        JsonGenerator_WriteString(generator, _expirationDate.c_str());
      }

      JsonGenerator_WriteFieldName(generator, "credentialSubject");
      _credentialSubject.ToOrderedJson(generator);

      JsonGenerator_WriteFieldName(generator, "proof");
      _proof.ToOrderJson(generator);

      JsonGenerator_WriteEndObject(generator);
    }
    */

  toJson(version: uint8_t): VerifiableCredentialJson {
    let j = <VerifiableCredentialJson>{};
    j["id"] = this._id;
    j["type"] = this._types;
    j["issuer"] = this._issuer;
    j["issuanceDate"] = this._issuanceDate;
    j["expirationDate"] = this._expirationDate;
    j["credentialSubject"] = this._credentialSubject.toJson(version);
    j["proof"] = this._proof.toJson(version);

    return j;
  }

  fromJson(j: VerifiableCredentialJson, version: uint8_t) {
    this._id = j["id"];

    if (j["type"]) {
      let types = j["type"];
      this._types = types;
    }

    if (j["issuer"]) {
      this._issuer = j["issuer"];
    }

    if (j["issuanceDate"]) {
      this._issuanceDate = j["issuanceDate"];
    }

    if (j["expirationDate"]) {
      this._expirationDate = j["expirationDate"];
    }

    if (j["credentialSubject"]) {
      this._credentialSubject = new CredentialSubject();
      this._credentialSubject.fromJson(j["credentialSubject"], version);
    }

    if (j["proof"]) {
      this._proof = new DIDProofInfo();
      this._proof.fromJson(j["proof"], version);
    }
  }
}

export class DIDPayloadProof {
  private _type: string;
  private _created: string;
  private _creator: string;
  private _signatureValue: string;

  constructor() {
    this._type = DID_DEFAULT_TYPE;
  }

  setType(type: string) {
    this._type = type;
  }

  getType(): string {
    return this._type;
  }

  setCreateDate(date: string) {
    this._created = date;
  }

  getCreatedDate(): string {
    return this._created;
  }

  setCreator(creator: string) {
    this._creator = creator;
  }

  getCreator(): string {
    return this._creator;
  }

  setSignature(signature: string) {
    this._signatureValue = signature;
  }

  getSignature(): string {
    return this._signatureValue;
  }

  toJson(version: uint8_t): DIDPayloadProofJson {
    let j = <DIDPayloadProofJson>{};

    j["type"] = this._type;

    if (!this._created) {
      j["created"] = this._created;
    }

    if (!this._creator) {
      j["creator"] = this._creator;
    }

    j["signatureValue"] = this._signatureValue;
    return j;
  }

  fromJson(j: DIDPayloadProofJson, version: uint8_t) {
    if (j["type"]) {
      this._type = j["type"];
    } else {
      this._type = DID_DEFAULT_TYPE;
    }

    if (j["created"]) {
      this._created = j["created"];
    }

    if (j["creator"]) {
      this._creator = j["creator"];
    }

    this._signatureValue = j["signatureValue"];
  }
}

export class DIDPayloadInfo {
  private _id: string;
  private _controller: string[];
  private _publickey: DIDPubKeyInfoArray;
  private _authentication: DIDPubKeyInfoArray; // contain 0 or 1
  private _authorization: DIDPubKeyInfoArray; // contain 0 or 1
  private _verifiableCredential: VerifiableCredentialArray; // contain 0 or 1
  private _services: ServiceEndpoints; // contain 0 or 1
  private _expires: string;
  private _proof: DIDPayloadProof;

  id(): string {
    return this._id;
  }

  setID(id: string) {
    this._id = id;
  }

  controller(): string[] {
    return this._controller;
  }

  publicKeyInfo(): DIDPubKeyInfoArray {
    return this._publickey;
  }

  setPublickKey(pubkey: DIDPubKeyInfoArray) {
    this._publickey = pubkey;
  }

  authentication(): DIDPubKeyInfoArray {
    return this._authentication;
  }

  setAuthentication(authentication: DIDPubKeyInfoArray) {
    this._authentication = authentication;
  }

  authorization(): DIDPubKeyInfoArray {
    return this._authorization;
  }

  setAuthorization(authorization: DIDPubKeyInfoArray) {
    this._authorization = authorization;
  }

  getVerifiableCredential(): VerifiableCredentialArray {
    return this._verifiableCredential;
  }

  setVerifiableCredential(verifiableCredential: VerifiableCredentialArray) {
    this._verifiableCredential = verifiableCredential;
  }

  getServiceEndpoint(): ServiceEndpoints {
    return this._services;
  }

  setServiceEndpoints(serviceEndpoint: ServiceEndpoints) {
    this._services = serviceEndpoint;
  }

  expires(): string {
    return this._expires;
  }

  setExpires(expires: string) {
    this._expires = expires;
  }

  setProof(proof: DIDPayloadProof) {
    this._proof = proof;
  }

  gGetProof(): DIDPayloadProof {
    return this._proof;
  }

  isValid(): boolean {
    let verifiedSign = false;
    if (this._proof.getType() != DID_DEFAULT_TYPE) {
      Log.error("unsupport did type");
      return false;
    }

    let proofID = this._proof.getCreator();
    if (!proofID) {
      proofID = PRIMARY_KEY;
    }

    if (proofID[0] == "#") {
      proofID = this._id + proofID;
    }

    for (let i = 0; i < this._publickey.length; i) {
      let pubkeyID = this._publickey[i].id();
      if (pubkeyID[0] == "#") pubkeyID = this._id + pubkeyID;

      if (proofID == pubkeyID) {
        let signature = Buffer.from(
          BASE64.decode(this._proof.getSignature()),
          "hex"
        );
        let pubkey = Base58.decode(this._publickey[i].publicKeyBase58());
        // TODO
        // if (
        //   EcdsaSigner.verify(
        //     pubkey,
        //     signature,
        //     Buffer.from(this.toOrderedJson(), "hex")
        //   )
        // ) {
        //   verifiedSign = true;
        // }
        break;
      }
    }

    return verifiedSign;
  }

  toJson(version: uint8_t): DIDPayloadInfoJson {
    let j = <DIDPayloadInfoJson>{};
    j["id"] = this._id;

    let jPubKey = [];
    for (let i = 0; i < this._publickey.length; ++i) {
      jPubKey.push(this._publickey[i].toJson(version));
    }

    j["publicKey"] = jPubKey;

    if (this._authentication) {
      let jAuthentication = [];
      for (let i = 0; i < this._authentication.length; ++i) {
        jAuthentication.push(this._authentication[i].toJson(version));
      }

      j["authentication"] = jAuthentication;
    }

    if (this._authorization) {
      let jAuthorization = [];
      for (let i = 0; i < this._authorization.length; ++i) {
        jAuthorization.push(this._authorization[i].toJson(version));
      }

      j["authorization"] = jAuthorization;
    }

    if (this._verifiableCredential) {
      let jVerifiableCredential = [];
      for (let i = 0; i < this._verifiableCredential.length; ++i) {
        jVerifiableCredential.push(
          this._verifiableCredential[i].toJson(version)
        );
      }
      j["verifiableCredential"] = jVerifiableCredential;
    }

    j["expires"] = this._expires;

    if (this._services) {
      let jService = [];
      for (let i = 0; i < this._services.length; ++i) {
        jService.push(this._services[i].toJson(version));
      }
      j["service"] = jService;
    }

    j["proof"] = this._proof.toJson(version);

    return j;
  }

  /*
    std::string DIDPayloadInfo::ToOrderedJson() const {
      JsonGenerator generator, *pGenerator;
      pGenerator = JsonGenerator_Initialize(&generator);
      JsonGenerator_WriteStartObject(pGenerator);

      JsonGenerator_WriteFieldName(pGenerator, "id");
      JsonGenerator_WriteString(pGenerator, _id.c_str());

      JsonGenerator_WriteFieldName(pGenerator, "publicKey");
      JsonGenerator_WriteStartArray(pGenerator);
      for (DIDPubKeyInfoArray::const_iterator it = _publickey.cbegin(); it != _publickey.cend(); ++it)
        (*it).ToOrderedJson(pGenerator);
      JsonGenerator_WriteEndArray(pGenerator);

      JsonGenerator_WriteFieldName(pGenerator, "authentication");
      JsonGenerator_WriteStartArray(pGenerator);
      for (DIDPubKeyInfoArray::const_iterator it = _authentication.cbegin(); it != _authentication.cend(); ++it)
        JsonGenerator_WriteString(pGenerator, (*it).ID().c_str());
      JsonGenerator_WriteEndArray(pGenerator);

      if (_authorization.size()) {
        JsonGenerator_WriteFieldName(pGenerator, "authorization");
        JsonGenerator_WriteStartArray(pGenerator);
        for (DIDPubKeyInfoArray::const_iterator it = _authorization.cbegin(); it != _authorization.cend(); ++it)
          JsonGenerator_WriteString(pGenerator, (*it).ID().c_str());
        JsonGenerator_WriteEndArray(pGenerator);
      }

      if (_verifiableCredential.size()) {
        JsonGenerator_WriteFieldName(pGenerator, "verifiableCredential");
        JsonGenerator_WriteStartArray(pGenerator);
        for (VerifiableCredentialArray::const_iterator it = _verifiableCredential.cbegin();
             it != _verifiableCredential.cend(); ++it) {
          (*it).ToOrderedJson(pGenerator);
        }
        JsonGenerator_WriteEndArray(pGenerator);
      }

      if (_services.size()) {
        JsonGenerator_WriteFieldName(pGenerator, "service");
        JsonGenerator_WriteStartArray(pGenerator);
        for (ServiceEndpoints::const_iterator it = _services.cbegin(); it != _services.cend(); ++it)
          (*it).ToOrderedJson(pGenerator);
        JsonGenerator_WriteEndArray(pGenerator);
      }

      if (_expires.size()){
        JsonGenerator_WriteStringField(pGenerator, "expires", _expires.c_str());
      }

      JsonGenerator_WriteEndObject(pGenerator);

      const char *pjson = JsonGenerator_Finish(pGenerator);
      std::string json = pjson;
      free((void *)pjson);
      return json;
    }
  */

  fromJson(j: DIDPayloadInfoJson, version: uint8_t) {
    if (j["controller"]) {
      if (Array.isArray(j)) {
        this._controller = j["controller"] as string[];
      } else {
        this._controller.push(j["controller"] as string);
      }
    } else {
      this._id = j["id"];
    }

    let jPubKey = j["publicKey"];
    this._publickey = [];
    for (let i = 0; i < jPubKey.length; ++i) {
      let pubKeyInfo = new DIDPubKeyInfo();
      pubKeyInfo.fromJson(jPubKey[i], version);
      pubKeyInfo.autoFill(this._id);
      this._publickey.push(pubKeyInfo);
    }

    if (j["authentication"]) {
      let jAuthentication = j["authentication"];
      this._authentication = [];
      for (let i = 0; i < jAuthentication.length; ++i) {
        let pubKeyInfo = new DIDPubKeyInfo();
        pubKeyInfo.fromJson(jAuthentication[i], version);
        pubKeyInfo.autoFill(this._id);
        this._authentication.push(pubKeyInfo);
      }
    }

    if (j["authorization"]) {
      let jAuthorization = j["authorization"];
      this._authorization = [];
      for (let i = 0; i < jAuthorization.length; ++i) {
        let pubKeyInfo = new DIDPubKeyInfo();
        pubKeyInfo.fromJson(jAuthorization[i], version);
        pubKeyInfo.autoFill(this._id);
        this._authorization.push(pubKeyInfo);
      }
    }

    this._expires = j["expires"] as string;

    if (j["verifiableCredential"]) {
      let jVerifiableCredential = j["verifiableCredential"];
      this._verifiableCredential = [];
      for (let i = 0; i < jVerifiableCredential.length; ++i) {
        let verifiableCredential = new VerifiableCredential();
        verifiableCredential.fromJson(jVerifiableCredential[i], version);
        verifiableCredential.autoFill(this._id);
        this._verifiableCredential.push(verifiableCredential);
      }
    }

    if (j["service"]) {
      let jservices = j["service"];
      this._services = [];
      for (let i = 0; i < jservices.length; ++i) {
        let serviceEndpoint = new ServiceEndpoint();
        serviceEndpoint.fromJson(jservices[i], version);
        serviceEndpoint.autoFill(this._id);
        this._services.push(serviceEndpoint);
      }
    }

    if (j["proof"]) {
      this._proof = new DIDPayloadProof();
      this._proof.fromJson(j["proof"], version);
    }
  }
}

export class DIDProofInfo {
  private _type: string;
  private _verificationMethod: string;
  private _signature: string;

  static newFromParams(method: string, signature: string, type: string) {
    let proofInfo = new DIDProofInfo();
    proofInfo._verificationMethod = method;
    proofInfo._signature = signature;
    proofInfo._type = type;
    return proofInfo;
  }

  type(): string {
    return this._type;
  }

  setType(type: string) {
    this._type = type;
  }

  verificationMethod(): string {
    return this._verificationMethod;
  }

  setVerificationMethod(method: string) {
    this._verificationMethod = method;
  }

  signature(): string {
    return this._signature;
  }

  setSignature(sign: string) {
    this._signature = sign;
  }

  estimateSize(version: uint8_t): size_t {
    let stream = new ByteStream();
    let size: size_t = 0;

    size += stream.writeVarUInt(this._type.length);
    size += this._type.length;
    size += stream.writeVarUInt(this._verificationMethod.length);
    size += this._verificationMethod.length;
    size += stream.writeVarUInt(this._signature.length);
    size += this._signature.length;

    return size;
  }

  serialize(stream: ByteStream, version: uint8_t) {
    stream.writeVarString(this._type);
    stream.writeVarString(this._verificationMethod);
    stream.writeVarString(this._signature);
  }

  deserialize(stream: ByteStream, version: uint8_t): boolean {
    this._type = stream.readVarString();
    if (!this._type) {
      Log.error("DIDProofInfo deserialize: type");
      return false;
    }

    this._verificationMethod = stream.readVarString();
    if (!this._verificationMethod) {
      Log.error("DIDProofInfo deserialize verificationMethod");
      return false;
    }

    this._signature = stream.readVarString();
    if (!this._signature) {
      Log.error("DIDProofInfo deserialize sign");
      return false;
    }

    return true;
  }

  autoFill(did: string) {
    if (this._verificationMethod[0] == "#") {
      this._verificationMethod = did + this._verificationMethod;
    }
  }

  /*
    toOrderJson(JsonGenerator *generator) const {
      JsonGenerator_WriteStartObject(generator);

      JsonGenerator_WriteStringField(generator, "type", _type.c_str());

      JsonGenerator_WriteStringField(generator, "verificationMethod", _verificationMethod.c_str());

      JsonGenerator_WriteStringField(generator, "signature", _signature.c_str());

      JsonGenerator_WriteEndObject(generator);
    }
  */

  equals(info: DIDProofInfo): boolean {
    return (
      this._type == info._type &&
      this._verificationMethod == info._verificationMethod &&
      this._signature == info._signature
    );
  }

  toJson(version: uint8_t): DIDProofInfoJson {
    let j = <DIDProofInfoJson>{};

    j["type"] = this._type;
    j["verificationMethod"] = this._verificationMethod;
    j["signature"] = this._signature;

    return j;
  }

  fromJson(j: DIDProofInfoJson, version: uint8_t) {
    if (j["type"]) {
      this._type = j["type"];
    } else {
      this._type = DID_DEFAULT_TYPE;
    }

    this._verificationMethod = j["verificationMethod"];
    this._signature = j["signature"];
  }
}

export class DIDInfo extends Payload {
  private _header: DIDHeaderInfo;
  private _payload: string;
  private _proof: DIDProofInfo;
  private _payloadInfo: DIDPayloadInfo;

  setDIDHeader(headerInfo: DIDHeaderInfo) {
    this._header = headerInfo;
  }

  didHeader(): DIDHeaderInfo {
    return this._header;
  }

  didPayloadString(): string {
    return this._payload;
  }

  setDIDPlayloadInfo(didPayloadInfo: DIDPayloadInfo) {
    this._payloadInfo = didPayloadInfo;
    let str = this._payloadInfo.toJson(0);
    this._payload = BASE64.encode(JSON.stringify(str));
  }

  didPayload(): DIDPayloadInfo {
    return this._payloadInfo;
  }

  setDIDProof(proofInfo: DIDProofInfo) {
    this._proof = proofInfo;
  }

  didProof(): DIDProofInfo {
    return this._proof;
  }

  estimateSize(version: uint8_t): size_t {
    let size: size_t = 0;

    size += this._header.estimateSize(version);
    size += this._payload.length;
    size += this._proof.estimateSize(version);

    return size;
  }

  serialize(stream: ByteStream, version: uint8_t) {
    this._header.serialize(stream, version);
    stream.writeVarString(this._payload);
    this._proof.serialize(stream, version);
  }

  deserialize(stream: ByteStream, version: uint8_t): boolean {
    this._header = new DIDHeaderInfo();
    if (!this._header.deserialize(stream, version)) {
      Log.error("DIDInfo deserialize header");
      return false;
    }

    this._payload = stream.readVarString();
    if (!this._payload) {
      Log.error("DIDInfo deserialize payload");
      return false;
    }

    this._proof = new DIDProofInfo();
    this._proof.deserialize(stream, version);
    if (!this._proof) {
      Log.error("DIDInfo deserialize proof");
      return false;
    }

    let payloadString = BASE64.decode(this._payload);
    this._payloadInfo = new DIDPayloadInfo();
    this._payloadInfo.fromJson(JSON.parse(payloadString), version);

    return true;
  }

  toJson(version: uint8_t): DIDInfoJson {
    let j = <DIDInfoJson>{};

    j["header"] = this._header.toJson(version);
    j["payload"] = this._payload;
    j["proof"] = this._proof.toJson(version);

    return j;
  }

  fromJson(j: DIDInfoJson, version: uint8_t) {
    this._header = new DIDHeaderInfo();
    this._header.fromJson(j["header"], version);
    this._payload = j["payload"];

    this._proof = new DIDProofInfo();
    this._proof.fromJson(j["proof"], version);

    let payloadString = BASE64.decode(this._payload);
    Log.info("did doc: {}", payloadString);
    this._payloadInfo = new DIDPayloadInfo();
    this._payloadInfo.fromJson(JSON.parse(payloadString), version);
  }

  isValid(version: uint8_t): boolean {
    let verifiedSign = false;

    if (this._proof.type() != DID_DEFAULT_TYPE) {
      Log.error("unsupport did type {}", this._proof.type());
      return false;
    }

    let proofID = this._proof.verificationMethod();
    if (!proofID) {
      Log.error("VerificationMethod of proof is empty");
      return false;
    }

    if (!this._payloadInfo.isValid()) {
      Log.error("did document verify signature fail");
      return false;
    }

    if (proofID[0] == "#") proofID = this._payloadInfo.id() + proofID;

    let sourceData = "";
    if (this._header.operation() == UPDATE_DID) {
      sourceData =
        this._header.specification() +
        this._header.operation() +
        this._header.previousTxid() +
        this._payload;
    } else {
      sourceData =
        this._header.specification() + this._header.operation() + this._payload;
    }

    const pubkeyInfoArray = this._payloadInfo.publicKeyInfo();
    for (let i = 0; i < pubkeyInfoArray.length; ++i) {
      let pubkeyID = pubkeyInfoArray[i].id();
      if (pubkeyID[0] == "#") pubkeyID = this._payloadInfo.id() + pubkeyID;

      if (proofID == pubkeyID) {
        let signature = BASE64.decode(this._proof.signature());
        let pubkey = Base58.decode(pubkeyInfoArray[i].publicKeyBase58());
        if (
          EcdsaSigner.verify(
            pubkey,
            Buffer.from(signature, "hex"),
            Buffer.from(sourceData, "hex")
          )
        ) {
          verifiedSign = true;
        }

        break;
      }
    }

    if (!verifiedSign) {
      Log.error("did payload verify signature fail");
    }

    return verifiedSign;
  }

  copyPayload(payload: Payload) {
    try {
      let didInfo = payload as DIDInfo;
      this.copyDIDInfo(didInfo);
    } catch (e) {
      Log.error("payload is not instance of CRInfo");
    }

    return this;
  }

  copyDIDInfo(payload: DIDInfo): DIDInfo {
    this._header = payload._header;
    this._payload = payload._payload;
    this._proof = payload._proof;

    this._payloadInfo = payload._payloadInfo;

    return this;
  }

  equals(p: DIDInfo, version: uint8_t): boolean {
    try {
      return (
        this._header.equals(p._header) &&
        this._payload == p._payload &&
        this._proof.equals(p._proof)
      );
    } catch (e) {
      Log.error("payload is not instance of DIDInfo");
    }

    return false;
  }
}
