var searchIndex = JSON.parse('{\
"warg_loader":{"doc":"","t":"DDEENNNNNNNNDNDNDNLLLLLLLLLLLLLLMLLLLLLLLLLLLLMLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLMMLLLLLALLLMMLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLMDEDDIEDRRNNNNDDNDDMMMMLLLLLLLLLLLLLLLLLLLLLKLLLLLLLLLLLLMMFMMMLLLLMMLLLLMLLLLLLLLLLLLLLLLLLLLLLLLLLLMFLMMMMMMLMLLLLLLLMMLLLLLLLLLLLLLMLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLL","n":["Client","ClientConfig","ContentHash","Error","InvalidConfig","InvalidContentHash","InvalidLabel","InvalidPackageManifest","InvalidPackageRef","IoError","NoRegistryForNamespace","OciError","PackageRef","RegistryMeta","Release","Sha256","Version","VersionError","borrow","borrow","borrow","borrow","borrow","borrow","borrow","borrow_mut","borrow_mut","borrow_mut","borrow_mut","borrow_mut","borrow_mut","borrow_mut","build","clone","clone","clone","clone","clone","clone_into","clone_into","clone_into","clone_into","clone_into","cmp","cmp_precedence","compare","content","copy_content","default","default_registry","eq","eq","equivalent","equivalent","equivalent","equivalent","equivalent","equivalent","fmt","fmt","fmt","fmt","fmt","fmt","fmt","fmt","fmt","from","from","from","from","from","from","from","from","from","from","from_default_config_file","from_default_file","from_file","from_str","from_str","from_str","from_toml","get_release","hash","hash","into","into","into","into","into","into","into","list_all_versions","major","minor","name","namespace","namespace_registry","new","new","oci_client","oci_registry_config","parse","partial_cmp","patch","pre","source","stream_content","to_client","to_owned","to_owned","to_owned","to_owned","to_owned","to_string","to_string","to_string","to_string","try_from","try_from","try_from","try_from","try_from","try_from","try_from","try_from","try_from","try_into","try_into","try_into","try_into","try_into","try_into","try_into","type_id","type_id","type_id","type_id","type_id","type_id","type_id","version","Certificate","CertificateEncoding","Client","ClientConfig","ClientConfigSource","ClientProtocol","Config","DEFAULT_MAX_CONCURRENT_DOWNLOAD","DEFAULT_MAX_CONCURRENT_UPLOAD","Der","Http","Https","HttpsExcept","ImageData","ImageLayer","Pem","PushResponse","TagResponse","accept_invalid_certificates","accept_invalid_hostnames","annotations","annotations","auth","borrow","borrow","borrow","borrow","borrow","borrow","borrow","borrow","borrow","borrow","borrow_mut","borrow_mut","borrow_mut","borrow_mut","borrow_mut","borrow_mut","borrow_mut","borrow_mut","borrow_mut","borrow_mut","client_config","clone","clone","clone","clone","clone","clone","clone_into","clone_into","clone_into","clone_into","clone_into","clone_into","config","config_url","current_platform_resolver","data","data","data","default","default","default","deserialize","digest","encoding","eq","equivalent","equivalent","equivalent","extra_root_certificates","fetch_manifest_digest","fmt","fmt","fmt","fmt","from","from","from","from","from","from","from","from","from","from","from_base64","from_source","into","into","into","into","into","into","into","into","into","into","layers","linux_amd64_resolver","list_tags","manifest","manifest_url","max_concurrent_download","max_concurrent_upload","media_type","media_type","mount_blob","name","new","new","new","oci_v1","oci_v1","oci_v1_from_config_file","oci_v1_gzip","platform_resolver","protocol","pull","pull_blob","pull_blob_stream","pull_image_manifest","pull_manifest","pull_manifest_and_config","push","push_blob","push_manifest","push_manifest_list","push_manifest_raw","sha256_digest","sha256_digest","tags","to_owned","to_owned","to_owned","to_owned","to_owned","to_owned","try_from","try_from","try_from","try_from","try_from","try_from","try_from","try_from","try_from","try_from","try_from","try_into","try_into","try_into","try_into","try_into","try_into","try_into","try_into","try_into","try_into","type_id","type_id","type_id","type_id","type_id","type_id","type_id","type_id","type_id","type_id"],"q":[[0,"warg_loader"],[144,"warg_loader::oci_client"],[315,"core::cmp"],[316,"core::result"],[317,"futures_io::if_std"],[318,"core::marker"],[319,"alloc::string"],[320,"core::convert"],[321,"core::fmt"],[322,"core::fmt"],[323,"std::io::error"],[324,"oci_distribution::errors"],[325,"core::option"],[326,"std::path"],[327,"core::convert"],[328,"alloc::vec"],[329,"core::error"],[330,"futures_core::stream"],[331,"core::any"],[332,"oci_distribution::reference"],[333,"oci_distribution::secrets"],[334,"oci_distribution::token_cache"],[335,"oci_distribution::manifest"],[336,"serde::de"],[337,"jwt::error"],[338,"core::marker"],[339,"oci_distribution::config"],[340,"tokio::io::async_write"],[341,"futures_core::stream"]],"d":["A read-only registry client.","Configuration for <code>super::Client</code>.","","","","","","","","","","","","","","","<strong>SemVer version</strong> as defined by https://semver.org.","","","","","","","","","","","","","","","","","","","","","","","","","","","","Compare the major, minor, patch, and pre-release value of …","","","Copies content into the given <code>AsyncWrite</code>.","","","","","","","","","","","","","","","","","","","","Returns the argument unchanged.","Returns the argument unchanged.","Returns the argument unchanged.","Returns the argument unchanged.","Returns the argument unchanged.","Returns the argument unchanged.","Returns the argument unchanged.","","","","Returns a new client configured from the default config …","","","","","","","Returns a <code>Release</code> for the given package version.","","","Calls <code>U::from(self)</code>.","Calls <code>U::from(self)</code>.","Calls <code>U::from(self)</code>.","Calls <code>U::from(self)</code>.","Calls <code>U::from(self)</code>.","Calls <code>U::from(self)</code>.","Calls <code>U::from(self)</code>.","Returns a list of all package <code>Version</code>s available for the …","","","","","","Returns a new client with the given <code>ClientConfig</code>.","Create <code>Version</code> with an empty pre-release and build …","Re-exported to ease configuration. OCI distribution client","","Create <code>Version</code> by parsing from string representation.","","","","","Returns a <code>TryStream</code> of content chunks.","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","A x509 certificate","The encoding of the certificate","The OCI client connects to an OCI registry and fetches OCI …","A client configuration","A source that can provide a <code>ClientConfig</code>. If you are using …","The protocol that the client should use to connect","The data and media type for a configuration object","Default value for <code>ClientConfig::max_concurrent_download</code>","Default value for <code>ClientConfig::max_concurrent_upload</code>","","","","","The data for an image or module.","The data and media type for an image layer","","The data returned by an OCI registry after a successful …","The data returned by a successful tags/list Request","Accept invalid certificates. Defaults to false","Accept invalid hostname. Defaults to false","This OPTIONAL property contains arbitrary metadata for …","This OPTIONAL property contains arbitrary metadata for …","Perform an OAuth v2 auth request if necessary.","","","","","","","","","","","","","","","","","","","","","Provides a <code>ClientConfig</code>.","","","","","","","","","","","","","The Configuration object of the image or module.","Pullable url for the config","A platform resolver that chooses the first variant …","The data of this layer","The data of this config object","Actual certificate","","","","","The digest of the image or module.","Which encoding is used by the certificate","","","","","A list of extra root certificate to trust. This can be …","Fetch a manifest’s digest from the remote OCI …","","","","","Returns the argument unchanged.","Returns the argument unchanged.","Returns the argument unchanged.","Returns the argument unchanged.","Returns the argument unchanged.","Returns the argument unchanged.","Returns the argument unchanged.","Returns the argument unchanged.","Returns the argument unchanged.","Returns the argument unchanged.","","Create a new client with the supplied config","Calls <code>U::from(self)</code>.","Calls <code>U::from(self)</code>.","Calls <code>U::from(self)</code>.","Calls <code>U::from(self)</code>.","Calls <code>U::from(self)</code>.","Calls <code>U::from(self)</code>.","Calls <code>U::from(self)</code>.","Calls <code>U::from(self)</code>.","Calls <code>U::from(self)</code>.","Calls <code>U::from(self)</code>.","The layers of the image or module.","A platform resolver that chooses the first linux/amd64 …","Fetches the available Tags for the given Reference","The manifest of the image or module.","Pullable url for the manifest","Maximum number of concurrent downloads to perform during a …","Maximum number of concurrent uploads to perform during a …","The media type of this layer","The media type of this object","Mounts a blob to the provided reference, from the given …","Repository Name","Create a new client with the supplied config","Constructs a new ImageLayer struct with provided data and …","Constructs a new Config struct with provided data and …","Constructs a new ImageLayer struct with provided data and …","Constructs a new Config struct with provided data and …","Construct a new Config struct with provided <code>ConfigFile</code> and …","Constructs a new ImageLayer struct with provided data and …","A function that defines the client’s behaviour if an …","Which protocol the client should use","Pull an image and return the bytes","Pull a single layer from an OCI registry.","Stream a single layer from an OCI registry.","Pull a manifest from the remote OCI Distribution service.","Pull a manifest from the remote OCI Distribution service.","Pull a manifest and its config from the remote OCI …","Push an image and return the uploaded URL of the image","Pushes a blob to the registry","Pushes the manifest for a specified image","Push a manifest list to an OCI registry.","Pushes the manifest, provided as raw bytes, for a …","Helper function to compute the sha256 digest of an image …","Helper function to compute the sha256 digest of this …","List of existing Tags","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","",""],"i":[0,0,0,0,9,9,9,9,9,9,9,9,0,9,0,5,0,9,8,1,2,3,4,5,9,8,1,2,3,4,5,9,1,1,2,3,4,5,1,2,3,4,5,1,1,1,4,8,2,2,1,3,1,1,1,3,3,3,1,1,3,3,4,5,5,9,9,8,1,2,3,4,5,9,9,9,9,8,2,2,1,3,5,2,8,1,3,8,1,2,3,4,5,9,8,1,1,3,3,2,8,1,0,2,1,1,1,1,9,8,2,1,2,3,4,5,1,3,5,9,8,1,2,3,3,4,5,5,9,8,1,2,3,4,5,9,8,1,2,3,4,5,9,4,0,0,0,0,0,0,0,0,0,40,42,42,42,0,0,40,0,0,29,29,38,39,33,58,33,29,37,45,38,39,40,41,42,58,33,29,37,45,38,39,40,41,42,50,37,38,39,40,41,42,37,38,39,40,41,42,37,58,0,38,39,41,33,29,42,45,37,41,42,42,42,42,29,33,45,40,41,42,58,33,29,37,45,38,39,40,41,42,45,33,58,33,29,37,45,38,39,40,41,42,37,0,33,37,58,29,29,38,39,33,45,33,38,39,38,39,39,38,29,29,33,33,33,33,33,33,33,33,33,33,33,38,39,45,37,38,39,40,41,42,58,33,33,29,37,45,38,39,40,41,42,58,33,29,37,45,38,39,40,41,42,58,33,29,37,45,38,39,40,41,42],"f":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,[-1,-2,[],[]],[-1,-2,[],[]],[-1,-2,[],[]],[-1,-2,[],[]],[-1,-2,[],[]],[-1,-2,[],[]],[-1,-2,[],[]],[-1,-2,[],[]],[-1,-2,[],[]],[-1,-2,[],[]],[-1,-2,[],[]],[-1,-2,[],[]],[-1,-2,[],[]],[-1,-2,[],[]],0,[1,1],[2,2],[3,3],[4,4],[5,5],[[-1,-2],6,[],[]],[[-1,-2],6,[],[]],[[-1,-2],6,[],[]],[[-1,-2],6,[],[]],[[-1,-2],6,[],[]],[[1,1],7],[[1,1],7],[[-1,-2],7,[],[]],0,[[8,3,5,-1],[[10,[6,9]]],[11,12]],[[],2],[[2,-1],2,[[14,[13]]]],[[1,1],15],[[3,3],15],[[-1,-2],15,[],[]],[[-1,-2],15,[],[]],[[-1,-2],15,[],[]],[[-1,-2],15,[],[]],[[-1,-2],15,[],[]],[[-1,-2],15,[],[]],[[1,16],[[10,[6,17]]]],[[1,16],[[10,[6,17]]]],[[3,16],18],[[3,16],18],[[4,16],18],[[5,16],18],[[5,16],18],[[9,16],18],[[9,16],18],[-1,-1,[]],[-1,-1,[]],[-1,-1,[]],[-1,-1,[]],[-1,-1,[]],[-1,-1,[]],[-1,-1,[]],[19,9],[20,9],[21,9],[[],[[10,[[22,[8]],9]]]],[[],[[10,[[22,[2]],9]]]],[-1,[[10,[2,9]]],[[24,[23]]]],[25,[[10,[1]]]],[25,[[10,[3]]]],[25,[[10,[5]]]],[25,[[10,[2,9]]]],[[8,3,1],[[10,[4,9]]]],[[1,-1],6,26],[[3,-1],6,26],[-1,-2,[],[]],[-1,-2,[],[]],[-1,-2,[],[]],[-1,-2,[],[]],[-1,-2,[],[]],[-1,-2,[],[]],[-1,-2,[],[]],[[8,3],[[10,[[27,[1]],9]]]],0,0,0,0,[[2,-1,-2],2,[[14,[13]]],[[14,[13]]]],[2,8],[[28,28,28],1],0,[[2,-1,[22,[29]],[22,[0]]],[[10,[2,9]]],[[14,[13]]]],[25,[[10,[1,19]]]],[[1,1],[[22,[7]]]],0,0,[9,[[22,[30]]]],[[8,3,5],[[10,[[0,[31]],9]]]],[2,8],[-1,-2,[],[]],[-1,-2,[],[]],[-1,-2,[],[]],[-1,-2,[],[]],[-1,-2,[],[]],[-1,13,[]],[-1,13,[]],[-1,13,[]],[-1,13,[]],[-1,[[10,[-2]]],[],[]],[-1,[[10,[-2]]],[],[]],[-1,[[10,[-2]]],[],[]],[-1,[[10,[-2]]],[],[]],[25,[[10,[3]]]],[-1,[[10,[-2]]],[],[]],[25,[[10,[5]]]],[-1,[[10,[-2]]],[],[]],[-1,[[10,[-2]]],[],[]],[-1,[[10,[-2]]],[],[]],[-1,[[10,[-2]]],[],[]],[-1,[[10,[-2]]],[],[]],[-1,[[10,[-2]]],[],[]],[-1,[[10,[-2]]],[],[]],[-1,[[10,[-2]]],[],[]],[-1,[[10,[-2]]],[],[]],[-1,32,[]],[-1,32,[]],[-1,32,[]],[-1,32,[]],[-1,32,[]],[-1,32,[]],[-1,32,[]],0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,[[33,34,35,36],[[10,[[22,[13]],21]]]],[-1,-2,[],[]],[-1,-2,[],[]],[-1,-2,[],[]],[-1,-2,[],[]],[-1,-2,[],[]],[-1,-2,[],[]],[-1,-2,[],[]],[-1,-2,[],[]],[-1,-2,[],[]],[-1,-2,[],[]],[-1,-2,[],[]],[-1,-2,[],[]],[-1,-2,[],[]],[-1,-2,[],[]],[-1,-2,[],[]],[-1,-2,[],[]],[-1,-2,[],[]],[-1,-2,[],[]],[-1,-2,[],[]],[-1,-2,[],[]],[-1,29,[]],[37,37],[38,38],[39,39],[40,40],[41,41],[42,42],[[-1,-2],6,[],[]],[[-1,-2],6,[],[]],[[-1,-2],6,[],[]],[[-1,-2],6,[],[]],[[-1,-2],6,[],[]],[[-1,-2],6,[],[]],0,0,[[[44,[43]]],[[22,[13]]]],0,0,0,[[],33],[[],29],[[],42],[-1,[[10,[45]]],46],0,0,[[42,42],15],[[-1,-2],15,[],[]],[[-1,-2],15,[],[]],[[-1,-2],15,[],[]],0,[[33,34,35],[[10,[13,21]]]],[[45,16],[[10,[6,17]]]],[[40,16],[[10,[6,17]]]],[[41,16],[[10,[6,17]]]],[[42,16],[[10,[6,17]]]],[-1,-1,[]],[-1,-1,[]],[-1,-1,[]],[-1,-1,[]],[-1,-1,[]],[-1,-1,[]],[-1,-1,[]],[-1,-1,[]],[-1,-1,[]],[-1,-1,[]],[-1,[[10,[-2,47]]],[[24,[[44,[48]]]],49],[]],[-1,33,50],[-1,-2,[],[]],[-1,-2,[],[]],[-1,-2,[],[]],[-1,-2,[],[]],[-1,-2,[],[]],[-1,-2,[],[]],[-1,-2,[],[]],[-1,-2,[],[]],[-1,-2,[],[]],[-1,-2,[],[]],0,[[[44,[43]]],[[22,[13]]]],[[33,34,35,[22,[51]],[22,[25]]],[[10,[45,21]]]],0,0,0,0,0,0,[[33,34,34,25],[[10,[6,21]]]],0,[29,33],[[[27,[48]],13,[22,[[52,[13,13]]]]],38],[[[27,[48]],13,[22,[[52,[13,13]]]]],39],[[[27,[48]],[22,[[52,[13,13]]]]],38],[[[27,[48]],[22,[[52,[13,13]]]]],39],[[53,[22,[[52,[13,13]]]]],[[10,[39,21]]]],[[[27,[48]],[22,[[52,[13,13]]]]],38],0,0,[[33,34,35,[27,[25]]],[[10,[37,21]]]],[[33,34,25,-1],[[10,[6,21]]],[54,12]],[[33,34,25],[[10,[[0,[55]],21]]]],[[33,34,35],[[10,[[6,[56,13]],21]]]],[[33,34,35],[[10,[[6,[57,13]],21]]]],[[33,34,35],[[10,[[6,[56,13,13]],21]]]],[[33,34,[44,[38]],39,35,[22,[56]]],[[10,[58,21]]]],[[33,34,[44,[48]],25],[[10,[13,21]]]],[[33,34,57],[[10,[13,21]]]],[[33,34,35,59],[[10,[13,21]]]],[[33,34,[27,[48]],60],[[10,[13,21]]]],[38,13],[39,13],0,[-1,-2,[],[]],[-1,-2,[],[]],[-1,-2,[],[]],[-1,-2,[],[]],[-1,-2,[],[]],[-1,-2,[],[]],[-1,[[10,[-2]]],[],[]],[-1,[[10,[-2]]],[],[]],[29,[[10,[33]]]],[-1,[[10,[-2]]],[],[]],[-1,[[10,[-2]]],[],[]],[-1,[[10,[-2]]],[],[]],[-1,[[10,[-2]]],[],[]],[-1,[[10,[-2]]],[],[]],[-1,[[10,[-2]]],[],[]],[-1,[[10,[-2]]],[],[]],[-1,[[10,[-2]]],[],[]],[-1,[[10,[-2]]],[],[]],[-1,[[10,[-2]]],[],[]],[-1,[[10,[-2]]],[],[]],[-1,[[10,[-2]]],[],[]],[-1,[[10,[-2]]],[],[]],[-1,[[10,[-2]]],[],[]],[-1,[[10,[-2]]],[],[]],[-1,[[10,[-2]]],[],[]],[-1,[[10,[-2]]],[],[]],[-1,[[10,[-2]]],[],[]],[-1,32,[]],[-1,32,[]],[-1,32,[]],[-1,32,[]],[-1,32,[]],[-1,32,[]],[-1,32,[]],[-1,32,[]],[-1,32,[]],[-1,32,[]]],"c":[],"p":[[3,"Version",0],[3,"ClientConfig",0],[3,"PackageRef",0],[3,"Release",0],[4,"ContentHash",0],[15,"tuple"],[4,"Ordering",315],[3,"Client",0],[4,"Error",0],[4,"Result",316],[8,"AsyncWrite",317],[8,"Unpin",318],[3,"String",319],[8,"Into",320],[15,"bool"],[3,"Formatter",321],[3,"Error",321],[6,"Result",321],[3,"Error",322],[3,"Error",323],[4,"OciDistributionError",324],[4,"Option",325],[3,"Path",326],[8,"AsRef",320],[15,"str"],[8,"Hasher",327],[3,"Vec",328],[15,"u64"],[3,"ClientConfig",144],[8,"Error",329],[8,"TryStream",330],[3,"TypeId",331],[3,"Client",144],[3,"Reference",332],[4,"RegistryAuth",333],[4,"RegistryOperation",334],[3,"ImageData",144],[3,"ImageLayer",144],[3,"Config",144],[4,"CertificateEncoding",144],[3,"Certificate",144],[4,"ClientProtocol",144],[3,"ImageIndexEntry",335],[15,"slice"],[3,"TagResponse",144],[8,"Deserializer",336],[4,"Error",337],[15,"u8"],[8,"Sized",318],[8,"ClientConfigSource",144],[15,"usize"],[3,"HashMap",338],[3,"ConfigFile",339],[8,"AsyncWrite",340],[8,"Stream",330],[3,"OciImageManifest",335],[4,"OciManifest",335],[3,"PushResponse",144],[3,"OciImageIndex",335],[3,"HeaderValue",341]],"b":[[58,"impl-Display-for-Version"],[59,"impl-Debug-for-Version"],[60,"impl-Debug-for-PackageRef"],[61,"impl-Display-for-PackageRef"],[63,"impl-Debug-for-ContentHash"],[64,"impl-Display-for-ContentHash"],[65,"impl-Display-for-Error"],[66,"impl-Debug-for-Error"],[74,"impl-From%3CError%3E-for-Error"],[75,"impl-From%3CError%3E-for-Error"],[76,"impl-From%3COciDistributionError%3E-for-Error"]]}\
}');
if (typeof window !== 'undefined' && window.initSearch) {window.initSearch(searchIndex)};
if (typeof exports !== 'undefined') {exports.searchIndex = searchIndex};
