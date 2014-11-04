/*
    This class maps the ZRTP C calls to ZRTP C++ methods.
    Copyright (C) 2010-2013  Werner Dittmann

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU Lesser General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.

*/

#include <libzrtpcpp/ZrtpCallback.h>
#include <libzrtpcpp/ZrtpConfigure.h>
#include <libzrtpcpp/ZIDCache.h>
#include <libzrtpcpp/ZRtp.h>
#include <libzrtpcpp/ZrtpCallbackWrapper.h>
#include <libzrtpcpp/ZrtpCWrapper.h>
#include <libzrtpcpp/ZrtpCrc32.h>

static int32_t zrtp_initZidFile(const char* zidFilename);

static ZRtp* getEngine(ZrtpContext* zrtpContext) {
    if (zrtpContext) {
        return (ZRtp*) zrtpContext->zrtpEngine;
    } else {
        return NULL;
    }
}

static ZrtpCallback* getCallback(ZrtpContext* zrtpContext) {
    if (zrtpContext) {
        return (ZrtpCallback*) zrtpContext->zrtpCallback;
    } else {
        return NULL;
    }
}

static ZrtpConfigure* getConfig(ZrtpContext* zrtpContext) {
    if (zrtpContext) {
        return (ZrtpConfigure*) zrtpContext->configure;
    } else {
        return NULL;
    }
}

ZrtpContext* zrtp_CreateWrapper() 
{
    ZrtpContext* zc = new ZrtpContext;
    zc->configure = 0;
    zc->zrtpEngine = 0;
    zc->zrtpCallback = 0;

    return zc;
}

void zrtp_initializeZrtpEngine(ZrtpContext* zrtpContext, 
                               zrtp_Callbacks *cb, const char* id,
                               const char* zidFilename,
                               void* userData,
                               int32_t mitmMode)
{
    ZrtpConfigure* configure = NULL;
    ZrtpCallback* callback = NULL;
    std::string clientIdString(id);

    zrtpContext->zrtpCallback = callback = new ZrtpCallbackWrapper(cb, zrtpContext);
    zrtpContext->userData = userData;

    if (zrtpContext->configure == 0) {
        zrtpContext->configure = configure = new ZrtpConfigure();
        configure->setStandardConfig();
    }

    // Initialize ZID file (cache) and get my own ZID
    zrtp_initZidFile(zidFilename);
    const unsigned char* myZid = getZidCacheInstance()->getZid();

    zrtpContext->zrtpEngine = new ZRtp((uint8_t*)myZid, callback,
                              clientIdString, configure, mitmMode == 0 ? false : true);
}

void zrtp_DestroyWrapper(ZrtpContext* zrtpContext) {

    if (zrtpContext == NULL)
        return;

    ZRtp* engine = getEngine(zrtpContext);
    ZrtpCallback* callback = getCallback(zrtpContext);
    ZrtpConfigure* configure = getConfig(zrtpContext);

    if (engine) {
        delete engine;
        zrtpContext->zrtpEngine = NULL;
    }

    if (callback) {
        delete callback;
        zrtpContext->zrtpCallback = NULL;
    }

    if (configure) {
        delete configure;
        zrtpContext->configure = NULL;
    }

    delete zrtpContext;
}

static int32_t zrtp_initZidFile(const char* zidFilename) {
    ZIDCache* zf = getZidCacheInstance();

    if (!zf->isOpen()) {
        std::string fname;
        if (zidFilename == NULL) {
            char *home = getenv("HOME");
            std::string baseDir = (home != NULL) ? (std::string(home) + std::string("/."))
                                  : std::string(".");
            fname = baseDir + std::string("GNUccRTP.zid");
            zidFilename = fname.c_str();
        }
        return zf->open((char *)zidFilename);
    }
    return 0;
}

int32_t zrtp_CheckCksum(uint8_t* buffer, uint16_t temp, uint32_t crc) 
{
    return zrtpCheckCksum(buffer, temp, crc);
}

uint32_t zrtp_GenerateCksum(uint8_t* buffer, uint16_t temp)
{
    return zrtpGenerateCksum(buffer, temp);
}

uint32_t zrtp_EndCksum(uint32_t crc)
{
    return zrtpEndCksum(crc);
}

/*
 * Applications use the following methods to control ZRTP, for example
 * to enable ZRTP, set flags etc.
 */
void zrtp_startZrtpEngine(ZrtpContext* zrtpContext) {
    ZRtp* engine = getEngine(zrtpContext);
    if ( engine )
        engine->startZrtpEngine();
}

void zrtp_stopZrtpEngine(ZrtpContext* zrtpContext) {
    ZRtp* engine = getEngine(zrtpContext);
    if (engine)
        engine->stopZrtp();
}

void zrtp_processZrtpMessage(ZrtpContext* zrtpContext, uint8_t *extHeader, uint32_t peerSSRC, size_t length) {
    ZRtp* engine = getEngine(zrtpContext);
    if (engine)
        engine->processZrtpMessage(extHeader, peerSSRC, length);
}

void zrtp_processTimeout(ZrtpContext* zrtpContext) {
    ZRtp* engine = getEngine(zrtpContext);
    if (engine)
        engine->processTimeout();
}

//int32_t zrtp_handleGoClear(ZrtpContext* zrtpContext, uint8_t *extHeader)
//{
//    if (zrtpContext && zrtpContext->zrtpEngine)
//        return zrtpContext->zrtpEngine->handleGoClear(extHeader) ? 1 : 0;
//
//    return 0;
//}

void zrtp_setAuxSecret(ZrtpContext* zrtpContext, uint8_t* data, int32_t length) {
    ZRtp* engine = getEngine(zrtpContext);
    if (engine)
        engine->setAuxSecret(data, length);
}

int32_t zrtp_inState(ZrtpContext* zrtpContext, int32_t state) {
    ZRtp* engine = getEngine(zrtpContext);
    if (engine)
        return engine->inState(state) ? 1 : 0;

    return 0;
}

void zrtp_SASVerified(ZrtpContext* zrtpContext) {
    ZRtp* engine = getEngine(zrtpContext);
    if (engine)
        engine->SASVerified();
}

void zrtp_resetSASVerified(ZrtpContext* zrtpContext) {
    ZRtp* engine = getEngine(zrtpContext);
    if (engine)
        engine->resetSASVerified();
}

char* zrtp_getHelloHash(ZrtpContext* zrtpContext, int32_t index) {
    std::string ret;
    ZRtp* engine = getEngine(zrtpContext);
    if (engine)
        ret = engine->getHelloHash(index);
    else
        return NULL;

    if (ret.size() == 0)
        return NULL;

    char* retval = (char*)malloc(ret.size()+1);
    strcpy(retval, ret.c_str());
    return retval;
}

char* zrtp_getPeerHelloHash(ZrtpContext* zrtpContext) {
    std::string ret;
    ZRtp* engine = getEngine(zrtpContext);
    if (engine)
        ret = engine->getPeerHelloHash();
    else
        return NULL;

    if (ret.size() == 0)
        return NULL;

    char* retval = (char*)malloc(ret.size()+1);
    strcpy(retval, ret.c_str());
    return retval;
}

char* zrtp_getMultiStrParams(ZrtpContext* zrtpContext, int32_t *length) {
    std::string ret;
    ZRtp* engine = getEngine(zrtpContext);

    *length = 0;
    if (engine)
        ret = engine->getMultiStrParams();
    else
        return NULL;

    if (ret.size() == 0)
        return NULL;

    *length = ret.size();
    char* retval = (char*) malloc(ret.size());
    ret.copy(retval, ret.size(), 0);
    return retval;
}

void zrtp_setMultiStrParams(ZrtpContext* zrtpContext, char* parameters, int32_t length) {
    ZRtp* engine = getEngine(zrtpContext);
    if (!engine)
        return;

    if (parameters == NULL)
        return;

    std::string str("");
    str.assign(parameters, length); // set chars (bytes) to the string

    engine->setMultiStrParams(str);
}

int32_t zrtp_isMultiStream(ZrtpContext* zrtpContext) {
    ZRtp* engine = getEngine(zrtpContext);
    if (engine)
        return engine->isMultiStream() ? 1 : 0;

    return 0;
}

int32_t zrtp_isMultiStreamAvailable(ZrtpContext* zrtpContext) {
    ZRtp* engine = getEngine(zrtpContext);
    if (engine)
        return engine->isMultiStreamAvailable() ? 1 : 0;

    return 0;
}

void zrtp_acceptEnrollment(ZrtpContext* zrtpContext, int32_t accepted) {
    ZRtp* engine = getEngine(zrtpContext);
    if (engine)
        return engine->acceptEnrollment(accepted == 0 ? false : true);
}

int32_t zrtp_isEnrollmentMode(ZrtpContext* zrtpContext) {
    ZRtp* engine = getEngine(zrtpContext);
    if (engine)
        return engine->isEnrollmentMode() ? 1 : 0;

    return 0;
}

void zrtp_setEnrollmentMode(ZrtpContext* zrtpContext, int32_t enrollmentMode) {
    ZRtp* engine = getEngine(zrtpContext);
    if (engine)
        return engine->setEnrollmentMode(enrollmentMode == 0 ? false : true);
}

int32_t isPeerEnrolled(ZrtpContext* zrtpContext) {
    ZRtp* engine = getEngine(zrtpContext);
    if (engine)
        return engine->isPeerEnrolled() ? 1 : 0;

    return 0;
}

int32_t zrtp_sendSASRelayPacket(ZrtpContext* zrtpContext, uint8_t* sh, char* render) {
    ZRtp* engine = getEngine(zrtpContext);
    if (engine) {
        std::string rn(render);
        return engine->sendSASRelayPacket(sh, rn) ? 1 : 0;
    }
    return 0;
}


const char* zrtp_getSasType(ZrtpContext* zrtpContext) {
    ZRtp* engine = getEngine(zrtpContext);
    if (engine) {
        std::string rn = engine->getSasType();
        if (rn.size() == 0)
            return NULL;

        char* retval = (char*)malloc(rn.size()+1);
        strcpy(retval, rn.c_str());
        return retval;
    }
    return NULL;
}


uint8_t* zrtp_getSasHash(ZrtpContext* zrtpContext) {
    ZRtp* engine = getEngine(zrtpContext);
    if (engine)
        return engine->getSasHash();

    return NULL;
}

int32_t zrtp_setSignatureData(ZrtpContext* zrtpContext, uint8_t* data, int32_t length) {
    ZRtp* engine = getEngine(zrtpContext);
    if (engine)
        return engine->setSignatureData(data, length) ? 1 : 0;

    return 0;
}

const uint8_t* zrtp_getSignatureData(ZrtpContext* zrtpContext) {
    ZRtp* engine = getEngine(zrtpContext);
    if (engine)
        return engine->getSignatureData();

    return 0;
}

int32_t zrtp_getSignatureLength(ZrtpContext* zrtpContext) {
    ZRtp* engine = getEngine(zrtpContext);
    if (engine)
        return engine->getSignatureLength();

    return 0;
}

void zrtp_conf2AckSecure(ZrtpContext* zrtpContext) {
    ZRtp* engine = getEngine(zrtpContext);
    if (engine)
        engine->conf2AckSecure();
}

int32_t zrtp_getPeerZid(ZrtpContext* zrtpContext, uint8_t* data) {
    if (data == NULL)
        return 0;

    ZRtp* engine = getEngine(zrtpContext);
    if (engine)
        return engine->getPeerZid(data);

    return 0;
}

int32_t zrtp_getNumberSupportedVersions(ZrtpContext* zrtpContext) {
    ZRtp* engine = getEngine(zrtpContext);
    if (engine)
        return engine->getNumberSupportedVersions();

    return 0;
}

int32_t zrtp_getCurrentProtocolVersion(ZrtpContext* zrtpContext) {
    ZRtp* engine = getEngine(zrtpContext);
    if (engine)
        return engine->getCurrentProtocolVersion();

    return 0;
}

/*
 * The following methods wrap the ZRTP Configure functions
 */
int32_t zrtp_InitializeConfig (ZrtpContext* zrtpContext)
{
    zrtpContext->configure = new ZrtpConfigure();
    return 1;
}

static EnumBase* getEnumBase(zrtp_AlgoTypes type)
{
        switch(type) {
        case zrtp_HashAlgorithm:
            return &zrtpHashes;
            break;

        case zrtp_CipherAlgorithm:
            return &zrtpSymCiphers;
            break;

        case zrtp_PubKeyAlgorithm:
            return &zrtpPubKeys;
            break;

        case zrtp_SasType:
            return &zrtpSasTypes;
            break;

        case zrtp_AuthLength:
            return &zrtpAuthLengths;
            break;

        default:
            return NULL;
    }
}

char** zrtp_getAlgorithmNames(ZrtpContext* zrtpContext, Zrtp_AlgoTypes type) 
{
    std::list<std::string>* names = NULL;
    EnumBase* base = getEnumBase(type);

    if (!base)
        return NULL;
    
    names = base->getAllNames();
    int size = base->getSize();
    char** cNames = new char* [size+1];
    cNames[size] = NULL;
    
    std::list<std::string >::iterator b = names->begin();
    std::list<std::string >::iterator e = names->end();

    for (int i = 0; b != e; b++, i++) {
        cNames[i] = new char [(*b).size()+1];
        strcpy(cNames[i], (*b).c_str());
    }
    return cNames;
}

void zrtp_freeAlgorithmNames(char** names)
{
    if (!names)
        return;
    
    for (char** cp = names; *cp; cp++)
        delete *cp;
    
    delete names;
}

void zrtp_setStandardConfig(ZrtpContext* zrtpContext)
{
    ZrtpConfigure* configure = getConfig(zrtpContext);
    if (configure)
        configure->setStandardConfig();
}

void zrtp_setMandatoryOnly(ZrtpContext* zrtpContext)
{
    ZrtpConfigure* configure = getConfig(zrtpContext);
    if (configure)
        configure->setMandatoryOnly();
}

int32_t zrtp_addAlgo(ZrtpContext* zrtpContext, zrtp_AlgoTypes algoType, const char* algo)
{
    EnumBase* base = getEnumBase(algoType);
    if (base) {
        AlgorithmEnum& a = base->getByName(algo);
        ZrtpConfigure* configure = getConfig(zrtpContext);
        if (configure)
            return configure->addAlgo((AlgoTypes)algoType, a);
    }

    //TODO: @wernerd Is this an appropriate return value in case of error?
    return 0;
}

int32_t zrtp_addAlgoAt(ZrtpContext* zrtpContext, zrtp_AlgoTypes algoType, const char* algo, int32_t index)
{
    EnumBase* base = getEnumBase(algoType);
    if (base) {
        AlgorithmEnum& a = base->getByName(algo);
        ZrtpConfigure* configure = getConfig(zrtpContext);
        if (configure)
            return configure->addAlgoAt((AlgoTypes)algoType, a, index);
    }

    //TODO: @wernerd Is this an appropriate return value in case of error?
    return 0;
}

int32_t zrtp_removeAlgo(ZrtpContext* zrtpContext, zrtp_AlgoTypes algoType, const char* algo)
{
    EnumBase* base = getEnumBase(algoType);
    if (base) {
        AlgorithmEnum& a = base->getByName(algo);
        ZrtpConfigure* configure = getConfig(zrtpContext);
        if (configure)
            return configure->removeAlgo((AlgoTypes)algoType, a);
    }

    //TODO: @wernerd Is this an appropriate return value in case of error?
    return 0;
}

int32_t zrtp_getNumConfiguredAlgos(ZrtpContext* zrtpContext, zrtp_AlgoTypes algoType)
{
    ZrtpConfigure* configure = getConfig(zrtpContext);
    if (configure)
        return configure->getNumConfiguredAlgos((AlgoTypes)algoType);

    return 0;
}

const char* zrtp_getAlgoAt(ZrtpContext* zrtpContext, Zrtp_AlgoTypes algoType, int32_t index)
{
    ZrtpConfigure* configure = getConfig(zrtpContext);
    if (configure) {
       AlgorithmEnum& a = configure->getAlgoAt((AlgoTypes)algoType, index);
       return a.getName();
    } else {
      //TODO: @wernerd Is this an appropriate return value in case of error?
      return NULL;
    }
}

int32_t zrtp_containsAlgo(ZrtpContext* zrtpContext, Zrtp_AlgoTypes algoType, const char*  algo)
{
    EnumBase* base = getEnumBase(algoType);
    if (base) {
        AlgorithmEnum& a = base->getByName(algo);
        ZrtpConfigure* configure = getConfig(zrtpContext);
        if (configure)
            return configure->containsAlgo((AlgoTypes)algoType, a) ? 1 : 0;
    }

    return 0;
}

void zrtp_setTrustedMitM(ZrtpContext* zrtpContext, int32_t yesNo)
{
    ZrtpConfigure* configure = getConfig(zrtpContext);
    if (configure)
        configure->setTrustedMitM(yesNo ? true : false);
}

int32_t zrtp_isTrustedMitM(ZrtpContext* zrtpContext)
{
    ZrtpConfigure* configure = getConfig(zrtpContext);
    if (configure)
        return configure->isTrustedMitM() ? 1 : 0;

    //TODO: @wernerd Is this an appropriate return value in case of error?
    return 0;
}

void zrtp_setSasSignature(ZrtpContext* zrtpContext, int32_t yesNo)
{
    ZrtpConfigure* configure = getConfig(zrtpContext);
    if (configure)
        configure->setSasSignature(yesNo ? true : false);
}

int32_t zrtp_isSasSignature(ZrtpContext* zrtpContext)
{
    ZrtpConfigure* configure = getConfig(zrtpContext);
    if (configure)
         return configure->isSasSignature() ? 1 : 0;

    //TODO: @wernerd Is this an appropriate return value in case of error?
    return 0;
}
