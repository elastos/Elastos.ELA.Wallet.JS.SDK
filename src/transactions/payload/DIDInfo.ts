// Copyright (c) 2012-2019 The Elastos Open Source Project
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

import { ByteStream } from "../../common/bytestream";
import { uint8_t, size_t, json, bytes_t, JSONArray } from "../../types";
import { Log } from "../../common/Log";
import { ErrorChecker, Error } from "../../common/ErrorChecker";
import { Base58 } from "../../walletcore/base58";
import { BASE64 } from "../../walletcore/base64";
import { DeterministicKey } from "../../walletcore/deterministickey";

export const DID_DEFAULT_TYPE = "ECDSAsecp256r1";
export const PREFIX_DID = "did:elastos:";
export const UPDATE_DID = "update";
export const PRIMARY_KEY = "#primary";

type DIDPubKeyInfoArray = DIDPubKeyInfo[];
type CredentialSubjectArray = CredentialSubject[];
type ServiceEndpoints = ServiceEndpoint[];
type VerifiableCredentialArray = VerifiableCredential[];

export class DIDHeaderInfo {
  private _specification: string;
  private _operation: string;
  private _previousTxid: string;

  constructor(specification: string, operation: string, preTxID: string) {
    this._specification = specification;
    this._operation = operation;
    this._previousTxid = preTxID;
    return this;
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
      if (!this.previousTxid) {
        Log.error("DIDHeaderInfo deserialize: previousTxid");
        return false;
      }
    }

    return true;
  }

  toJson(version: uint8_t): json {
    let j: json;
    j["specification"] = this._specification;
    j["operation"] = this._operation;
    if (this._operation == UPDATE_DID) {
      j["previousTxid"] = this._previousTxid;
    }
    return j;
  }

  fromJson(j: json, version: uint8_t) {
    this._specification = j["specification"] as string;
    this._operation = j["operation"] as string;

    if (this._operation == UPDATE_DID) {
      this._previousTxid = j["previousTxid"] as string;
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

  toJson(version: uint8_t): json {
    let j: json;

    j["id"] = this._id;
    j["type"] = this._type;

    if (!this._controller) {
      j["controller"] = this._controller;
    }

    j["publicKeyBase58"] = this._publicKeyBase58;

    return j;
  }

  fromJson(j: json, version: uint8_t) {
    if (j["id"]) {
      this._id = j["id"] as string;
      this._publicKeyBase58 = j["publicKeyBase58"] as string;
    } else if (typeof j === "string") {
      this._id = j;
    }

    if (j["type"]) {
      this._type = j["type"] as string;
    } else {
      this._type = DID_DEFAULT_TYPE;
    }

    if (j["controller"]) {
      this._controller = j["controller"] as string;
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
  private _properties: json;

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

  getProperties(): json {
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
  toJson(version: uint8_t): json {
    let j = this._properties;
    j["id"] = this._id;
    return j;
  }

  fromJson(j: json, version: uint8_t) {
    if (j["id"]) {
      this._id = j["id"] as string;
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

  constructor(id: string, type: string, serviceEndpoint: string) {
    this._id = id;
    this._type = type;
    this._serviceEndpoint = serviceEndpoint;
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
  toJson(version: uint8_t): json {
    let j: json;

    j["id"] = this._id;
    j["type"] = this._type;
    j["serviceEndpoint"] = this._serviceEndpoint;

    return j;
  }

  fromJson(j: json, version: uint8_t) {
    if (j["id"]) this._id = j["id"] as string;

    if (j["type"]) this._type = j["type"] as string;

    if (j["serviceEndpoint"])
      this._serviceEndpoint = j["serviceEndpoint"] as string;
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

  toJson(version: uint8_t): json {
    let j: json;
    j["id"] = this._id;
    j["type"] = this._types;
    j["issuer"] = this._issuer;
    j["issuanceDate"] = this._issuanceDate;
    j["expirationDate"] = this._expirationDate;
    j["credentialSubject"] = this._credentialSubject.toJson(version);
    j["proof"] = this._proof.toJson(version);

    return j;
  }

  fromJson(j: json, version: uint8_t) {
    this._id = j["id"] as string;

    if (j["type"]) {
      let types = j["type"] as string[];
      this._types = types;
    }

    if (j["issuer"]) {
      this._issuer = j["issuer"] as string;
    }

    if (j["issuanceDate"]) {
      this._issuanceDate = j["issuanceDate"] as string;
    }

    if (j["expirationDate"]) {
      this._expirationDate = j["expirationDate"] as string;
    }

    if (j["credentialSubject"]) {
      this._credentialSubject = j["credentialSubject"].fromJson(version);
    }

    if (j["proof"]) {
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

  toJson(version: uint8_t): json {
    let j: json;

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

  fromJson(j: json, version: uint8_t) {
    if (j["type"]) {
      this._type = j["type"] as string;
    } else {
      this._type = DID_DEFAULT_TYPE;
    }

    if (j["created"]) {
      this._created = j["created"] as string;
    }

    if (j["creator"]) {
      this._creator = j["creator"] as string;
    }

    this._signatureValue = j["signatureValue"] as string;
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
        // TODO
        let signature: bytes_t = Buffer.from(
          BASE64.decode(this._proof.getSignature())
        );
        let pubkey: bytes_t = Base58.decode(
          this._publickey[i].publicKeyBase58()
        );
        let key: DeterministicKey = new DeterministicKey(
          DeterministicKey.ELASTOS_VERSIONS
        );
        key.publicKey = pubkey;
        if (key.verify(this.toOrderedJson(), signature)) {
          verifiedSign = true;
        }
        break;
      }
    }

    return verifiedSign;
  }

  toJson(version: uint8_t): json {
    let j: json;
    j["id"] = this._id;

    let jPubKey: JSONArray;
    for (let i = 0; i < this._publickey.length; ++i) {
      jPubKey.push(this._publickey[i].toJson(version));
    }

    j["publicKey"] = jPubKey;

    if (this._authentication) {
      let jAuthentication: JSONArray;
      for (let i = 0; i < this._authentication.length; ++i) {
        jAuthentication.push(this._authentication[i].toJson(version));
      }

      j["authentication"] = jAuthentication;
    }

    if (this._authorization) {
      let jAuthorization: JSONArray;
      for (let i = 0; i < this._authorization.length; ++i) {
        jAuthorization.push(this._authorization[i].toJson(version));
      }

      j["authorization"] = jAuthorization;
    }

    if (this._verifiableCredential) {
      let jVerifiableCredential: JSONArray;
      for (let i = 0; i < this._verifiableCredential.length; ++i) {
        jVerifiableCredential.push(
          this._verifiableCredential[i].toJson(version)
        );
      }
      j["verifiableCredential"] = jVerifiableCredential;
    }

    j["expires"] = this._expires;

    if (this._services) {
      let jService: JSONArray;
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

		void DIDPayloadInfo::FromJson(const nlohmann::json &j, uint8_t version) {
		    if (j.contains("controller")) {
                if (j.is_array()) {
                    _controller = j["controller"].get<std::vector<std::string>>();
                } else {
                    _controller.push_back(j["controller"].get<std::string>());
                }
		    } else {
                _id = j["id"].get<std::string>();
		    }

#if 0
			nlohmann::json jPubKey = j["publicKey"];
			for (nlohmann::json::iterator it = jPubKey.begin(); it != jPubKey.end(); ++it) {
				DIDPubKeyInfo pubKeyInfo;
				pubKeyInfo.FromJson(*it, version);
				pubKeyInfo.AutoFill(_id);
				_publickey.push_back(pubKeyInfo);
			}

			if (j.find("authentication") != j.end()) {
				nlohmann::json jAuthentication = j["authentication"];
				for (nlohmann::json::iterator it = jAuthentication.begin(); it != jAuthentication.end(); ++it) {
					DIDPubKeyInfo pubKeyInfo;
					pubKeyInfo.FromJson(*it, version);
					pubKeyInfo.AutoFill(_id);
					_authentication.push_back(pubKeyInfo);
				}
			}

			if (j.find("authorization") != j.end()) {
				nlohmann::json jAuthorization = j["authorization"];
				for (nlohmann::json::iterator it = jAuthorization.begin(); it != jAuthorization.end(); ++it) {
					DIDPubKeyInfo pubKeyInfo;
					pubKeyInfo.FromJson(*it, version);
					pubKeyInfo.AutoFill(_id);
					_authorization.push_back(pubKeyInfo);
				}
			}

			_expires = j["expires"].get<std::string>();

			if (j.find("verifiableCredential") != j.end()) {
				nlohmann::json jVerifiableCredential = j["verifiableCredential"];
				for (nlohmann::json::iterator it = jVerifiableCredential.begin(); it != jVerifiableCredential.end(); ++it) {
					VerifiableCredential verifiableCredential;
					verifiableCredential.FromJson(*it, version);
					verifiableCredential.AutoFill(_id);
					_verifiableCredential.push_back(verifiableCredential);
				}
			}

			if (j.find("service") != j.end()) {
				nlohmann::json jservices = j["service"];
				for (nlohmann::json::iterator it = jservices.begin(); it != jservices.end(); ++it) {
					ServiceEndpoint serviceEndpoint;
					serviceEndpoint.FromJson(*it, version);
					serviceEndpoint.AutoFill(_id);
					_services.push_back(serviceEndpoint);
				}
			}

			if (j.find("proof") != j.end()) {
				_proof.FromJson(j["proof"], version);
			}
#endif
		}*/
}

export class DIDProofInfo {
  private _type: string;
  private _verificationMethod: string;
  private _signature: string;

  constructor(method: string, signature: string, type: string) {
    this._verificationMethod = method;
    this._signature = signature;
    this._type = type;
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

  toJson(version: uint8_t): json {
    let j: json;

    j["type"] = this._type;
    j["verificationMethod"] = this._verificationMethod;
    j["signature"] = this._signature;

    return j;
  }

  fromJson(j: json, version: uint8_t) {
    if (j["type"]) {
      this._type = j["type"] as string;
    } else {
      this._type = DID_DEFAULT_TYPE;
    }

    this._verificationMethod = j["verificationMethod"] as string;
    this._signature = j["signature"] as string;
  }
}

export class DIDInfo {
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
    // TODO
    let str: string = this._payloadInfo.toJson(0);
    this._payload = BASE64.encode(str);
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
    if (!this._header.deserialize(stream, version)) {
      Log.error("DIDInfo deserialize header");
      return false;
    }

    this._payload = stream.readVarString();
    if (!this._payload) {
      Log.error("DIDInfo deserialize payload");
      return false;
    }

    this._proof.deserialize(stream, version);
    if (!this._proof) {
      Log.error("DIDInfo deserialize proof");
      return false;
    }

    // TODO
    // bytes_t bytes = Base64::DecodeURL(_payload);
    // std::string payloadString((char *) bytes.data(), bytes.size());
    // _payloadInfo.FromJson(nlohmann::json::parse(payloadString), version);

    return true;
  }

  toJson(version: uint8_t): json {
    let j: json;

    j["header"] = this._header.toJson(version);
    j["payload"] = this._payload;
    j["proof"] = this._proof.toJson(version);

    return j;
  }

  /*
		void DIDInfo::FromJson(const nlohmann::json &j, uint8_t version) {
			_header.FromJson(j["header"], version);
			_payload = j["payload"].get<std::string>();
			_proof.FromJson(j["proof"], version);

			bytes_t bytes = Base64::DecodeURL(_payload);
			std::string payloadString((char *) bytes.data(), bytes.size());
			SPVLOG_DEBUG("did doc: {}", payloadString);
			_payloadInfo.FromJson(nlohmann::json::parse(payloadString), version);
		}

		bool DIDInfo::IsValid(uint8_t version) const {
			bool verifiedSign = false;

			if (_proof.Type() != DID_DEFAULT_TYPE) {
				Log::error("unsupport did type {}", _proof.Type());
				return false;
			}
#if 1
			return true;
#else
			std::string proofID = _proof.VerificationMethod();
			if (proofID.empty()) {
				Log::error("VerificationMethod of proof is empty");
				return false;
			}

			if (!_payloadInfo.IsValid()) {
				Log::error("did document verify signature fail");
				return false;
			}

			if (proofID[0] == '#')
				proofID = _payloadInfo.ID() + proofID;

			std::string sourceData = "";
			if (_header.Operation() == UPDATE_DID) {
				sourceData = _header.Specification() + _header.Operation() + _header.PreviousTxid() + _payload;
			} else {
				sourceData = _header.Specification() + _header.Operation() + _payload;
			}

			const DIDPubKeyInfoArray &pubkeyInfoArray = _payloadInfo.PublicKeyInfo();
			for (DIDPubKeyInfoArray::const_iterator it = pubkeyInfoArray.cbegin(); it != pubkeyInfoArray.cend(); ++it) {
				std::string pubkeyID = (*it).ID();
				if (pubkeyID[0] == '#')
					pubkeyID = _payloadInfo.ID() + pubkeyID;

				if (proofID == pubkeyID) {
					bytes_t signature = Base64::DecodeURL(_proof.Signature());
					bytes_t pubkey = Base58::Decode((*it).PublicKeyBase58());
					Key key;
					key.SetPubKey(pubkey);

					if (key.Verify(sourceData, signature)) {
						verifiedSign = true;
					}

					break;
				}
			}

			if (!verifiedSign) {
				Log::error("did payload verify signature fail");
			}

			return verifiedSign;
#endif
		}

		IPayload &DIDInfo::operator=(const IPayload &payload) {
			try {
				const DIDInfo &didInfo = dynamic_cast<const DIDInfo &>(payload);
				operator=(didInfo);
			} catch (const std::bad_cast &e) {
				Log::error("payload is not instance of CRInfo");
			}

			return *this;
		}
		*/

  copyFromDIDInfo(payload: DIDInfo): DIDInfo {
    this._header = payload._header;
    this._payload = payload._payload;
    this._proof = payload._proof;

    this._payloadInfo = payload._payloadInfo;

    return this;
  }

  equals(p: DIDInfo, version: uint8_t): boolean {
    try {
      return (
        this._header == p._header &&
        this._payload == p._payload &&
        this._proof == p._proof
      );
    } catch (e) {
      Log.error("payload is not instance of DIDInfo");
    }

    return false;
  }
}
