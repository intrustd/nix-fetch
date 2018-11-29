#include <deque>
#include <fstream>
#include <sstream>
#include <algorithm>
#include <iostream>
#include <iterator>

#include <nix/config.h>
#include <nix/store-api.hh>
#include <nix/shared.hh>
#include <nix/types.hh>
#include <nix/crypto.hh>
#include <nix/derivations.hh>
#include <nix/logging.hh>

// Read in file of <store-path> <signatures> (either stdin or a file),
// and also /etc/nix-kite-stores
//
// Read in nix paths on command line
//
// For each path in the closure, verify that the paths exist in the
// store and are signed by any of the public keys. If they are not
// signed by a key, check to see if it is equal to a path signed by a
// public key in a trusted store. If so, accept
//
// For all paths not in the store, attempt to find it in the remote
// store, by going through each in order. If a closure is downloaded
// from a system store, make sure none of its dependencies are from an
// app store.
//
// At the end of this, we have a list of paths and a list of stores to
// fetch from.
//
// TODO For each unique store, copy paths in parallel
//
// Copy each path reporting progress, checking signatures as we go
// along
//
// Finally, verify the downloaded path. If it's not okay, delete all
// downloaded paths from the store.

class CacheInfo {
public:
  enum CacheType { SystemCache,
                   AppCache };

  CacheInfo()
    : m_store(nullptr), m_type(AppCache) {
  }

  CacheInfo(const std::string &cache_uri,
            nix::PublicKeys &&keys,
            CacheType type)
    : m_cache_uri(cache_uri),
      m_store(nix::openStore(cache_uri)),
      m_keys(std::move(keys)),
      m_type(type) {
  }

  const std::string &cache_uri() const { return m_cache_uri; }
  const nix::ref<nix::Store> &store() const { return m_store; }
  const nix::PublicKeys &keys() const { return m_keys; }

  CacheType type() const { return m_type; }

  bool verify_sigs(const nix::ValidPathInfo &p) const {
    return p.checkSignatures(*store(), keys()) > 0;
  }

  void add_public_keys(const nix::PublicKeys &keys) {
    for ( auto key: keys ) {
      auto existing(m_keys.find(key.first));
      if ( existing == m_keys.end() ) {
        m_keys.emplace(key.first, std::move(key.second));
      } else {
        if ( existing->second.key != key.second.key )
          throw nix::Error(nix::format("Key mismatch at %s (in cache %s)") % key.first % cache_uri());
      }
    }
  }

private:
  std::string m_cache_uri;
  nix::ref<nix::Store> m_store;
  nix::PublicKeys m_keys;
  CacheType m_type;
};

class CacheIterator {
public:

  CacheInfo &operator*() {
    auto ret(m_caches.find(*m_i));
    if ( ret == m_caches.end() )
      throw std::runtime_error("CacheIterator: no cache found");

    return ret->second;
  }

  const CacheInfo &operator*() const {
    return m_caches[*m_i];
  }

  CacheInfo *operator->() {
    return &(**this);
  }

  CacheIterator &operator++() {
    m_i++;
    return *this;
  }

  CacheIterator &operator++(int i) {
    m_i++;
    return *this;
  }

  bool operator==(const CacheIterator &b) const {
    return m_i == b.m_i;
  }

  bool operator!=(const CacheIterator &b) const {
    return !(*this == b);
  }

private:
  CacheIterator( std::map<std::string, CacheInfo> &caches,
                 std::list<std::string>::iterator i)
    : m_caches(caches), m_i(i) {
  }

  std::map<std::string, CacheInfo> &m_caches;
  std::list<std::string>::iterator m_i;

  friend class CacheSpec;
};

template<>
struct std::iterator_traits<CacheIterator> {
  typedef std::iterator_traits<std::list<std::string>::iterator>::difference_type difference_type;
  typedef std::iterator_traits<std::list<std::string>::iterator>::value_type value_type;
  typedef std::iterator_traits<std::list<std::string>::iterator>::pointer pointer;
  typedef std::iterator_traits<std::list<std::string>::iterator>::iterator_category iterator_category;
};

class CacheSpec {
public:
  CacheSpec() {
  }

  typedef CacheInfo value_type;
  typedef CacheIterator iterator;

  iterator begin() {
    return CacheIterator(m_caches, m_cache_order.begin());
  }

  iterator end() {
    return CacheIterator(m_caches, m_cache_order.end());
  }

  void read_system() {
    const char *path(getenv("KITE_CACHES"));

    if ( !path ) path = "/etc/kite/caches";

    std::fstream is(path, std::fstream::in);

    if ( !is ) {
      std::cerr << "Could not open " << path << std::endl;
    } else {
      load_from_stream(is, CacheInfo::SystemCache);
    }
  }

  void load_from_stream(std::istream &is, CacheInfo::CacheType type) {
    while (!is.eof()) {
      std::string line;

      std::getline(is, line);

      std::stringstream lines(line);

      std::string cache_uri;
      nix::PublicKeys public_keys;

      lines >> cache_uri;

      if ( cache_uri.size() == 0 && lines.eof() ) continue;

      while ( !lines.eof() ) {
        std::string public_key_spec;
        lines >> public_key_spec;

        if ( public_key_spec.size() == 0 && lines.eof() ) break;

        nix::PublicKey public_key(public_key_spec);
        public_keys.emplace(public_key.name, std::move(public_key));
      }

      if ( m_caches.find(cache_uri) != m_caches.end() ) {
        m_caches[cache_uri].add_public_keys(public_keys);
      } else {
        auto i(m_caches.emplace(std::piecewise_construct,
                                std::forward_as_tuple(cache_uri),
                                std::forward_as_tuple(cache_uri, std::move(public_keys), type)));
        m_cache_order.emplace_back(cache_uri);
      }
    }
  }

  iterator determine_provenance(const nix::ValidPathInfo &p) {
    return std::find_if(begin(), end(), [&p] (auto cache) { return cache.verify_sigs(p); });
  }

private:
  std::map< std::string, CacheInfo > m_caches;
  std::list< std::string > m_cache_order;
};

class DownloadSource {
public:
  enum Source { Local, Remote };

  DownloadSource(CacheInfo::CacheType p)
    : m_source(Local), m_cache(NULL), m_provenance(p) {
  }

  DownloadSource(const CacheInfo &cache)
    : m_source(Remote), m_cache(&cache), m_provenance(cache.type()) {
  }

  bool is_remote() const { return m_cache; }
  const CacheInfo &cache() const { return *m_cache; }
  CacheInfo::CacheType provenance() const { return m_provenance; }

private:
  Source m_source;
  const CacheInfo *m_cache;
  CacheInfo::CacheType m_provenance;
};

void usage() {
  std::cerr << "nix-fetch -- Fetch substitutes from a binary cache" << std::endl;
  std::cerr << "Usage: nix-fetch store [--allow-unsigned] [--public-key PUBKEY] [paths...]" << std::endl << std::endl;
  std::cerr << "Options:" << std::endl;
  std::cerr << "   --help             Display this help message" << std::endl;
  std::cerr << "   --public-key PKEY  Accept paths using this key" << std::endl;
  std::cerr << "   --allow-unsigned   Accept local paths that have not been signed" << std::endl;
}

void addPublicKeys(const std::list<const char*> ourKeys) {
  std::stringstream keysStr;

  std::copy(ourKeys.begin(), ourKeys.end(),
            std::ostream_iterator<const char*>(keysStr, " "));

  nix::globalConfig.set("trusted-public-keys", keysStr.str());
}

int main(int argc, char **argv) {
  std::deque< std::pair<std::string, CacheInfo::CacheType> > paths;
  std::list< std::string > pathOrder;
  CacheSpec caches;
  bool bAllowUnsourced(false), bVerbose(false);

  caches.read_system();

  for ( int i = 1; i < argc; ++i ) {
    std::string arg(argv[i]);
    if ( arg == "--caches" ) {
      if ( (i + 1) >= argc ) {
        std::cerr << "Missing argument for --caches" << std::endl;
        return 1;
      } else {
        std::fstream is(argv[++i], std::fstream::in);

        if ( !is ) {
          std::cerr << "Could not open " << arg << std::endl;
          return 1;
        }

        caches.load_from_stream(is, CacheInfo::AppCache);
      }
    } else if ( arg == "--allow-unsourced" ) {
      bAllowUnsourced = true;
    } else if ( arg == "--verbose" ) {
      bVerbose = true;
    } else {
      pathOrder.emplace_front(arg);
      paths.emplace_back(std::make_pair(std::move(arg), CacheInfo::AppCache));
    }
  }

  std::map< std::string, DownloadSource > sources;
  auto localStore(nix::openStore());

  // Attempt find the requested derivations in each of the stores
  while ( !paths.empty() ) {
    auto pathAndProv(std::move(*paths.begin()));
    std::string path(std::move(pathAndProv.first));
    CacheInfo::CacheType provenance(pathAndProv.second);
    paths.pop_front();

    if ( sources.find(path) != sources.end() )
      continue;

    try {
      auto found(localStore->queryPathInfo(path));

      CacheSpec::iterator prov(caches.determine_provenance(*found));

      if ( prov == caches.end() ) {
        if ( found->ultimate || (bAllowUnsourced && found->sigs.empty()) )
          sources.emplace(path, DownloadSource(CacheInfo::SystemCache));
        else {
          // Otherwise, check if any remote store has this path.
          //
          // If so, verify that the hashes match.
          for ( auto cache: caches ) {
            try {
              auto remote(cache.store()->queryPathInfo(path));

              if ( remote->narHash == found->narHash &&
                   cache.verify_sigs(*remote) ) {
                sources.emplace(path, DownloadSource(cache.type()));
                break;
              }
            } catch (nix::InvalidPath &) {
            }
          }

          if ( sources.find(path) == sources.end() ) {
            throw nix::Error(nix::format("Local dependency is not properly signed and doesn't match: %s") % path);
          }
        }
      } else {
        sources.emplace(path, DownloadSource(prov->type()));
      }
    } catch ( nix::InvalidPath & ) {
      std::cerr << "Querying caches for " << path << std::endl;

      auto cache(std::find_if(caches.begin(), caches.end(),
                              [&path]( const CacheInfo &cache ) {
                                try {
                                  auto found(cache.store()->queryPathInfo(path));
                                  return true;
                                } catch (nix::InvalidPath &p) {
                                  return false;
                                }
                              }));

      if ( cache == caches.end() ) {
        std::cerr << "Could not find store path " << path << " in any cache" << std::endl;
        return 2;
      }

      // Otherwise, check that if we're downloading this, that a system
      // path isn't depending on an app path.
      if ( provenance == CacheInfo::SystemCache &&
           cache->type() == CacheInfo::AppCache ) {
        std::cerr << "Path dependencies permissions violation at " << path << std::endl;
        return 3;
      }

      sources.emplace(path, DownloadSource(*cache));

      auto found(cache->store()->queryPathInfo(path));

      if ( !cache->verify_sigs(*found) ) {
        throw nix::Error(nix::format("Signature for %s in %s is invalid\n") % path % cache->cache_uri());
      }

      for ( auto ref: found->references ) {
        auto existing_source(sources.find(ref));
        if ( existing_source == sources.end() ) {
          pathOrder.push_front(ref);
          paths.push_back(std::make_pair(ref, cache->type()));
        } else {
          if ( existing_source->second.provenance() == CacheInfo::AppCache &&
               cache->type() == CacheInfo::SystemCache ) {
            throw nix::Error(nix::format("The system package %s depends on the app package %s") % path % ref);
          }
        }
      }
    }
  }

  size_t totalNarSize(0), pathCnt(0);
  // For all packages, determine the download size
  for ( auto source: sources ) {
    if ( bVerbose ) {
      std::cerr << "[" << source.first << "] ";
      std::cerr << (source.second.provenance() == CacheInfo::SystemCache ? "SYS" : "APP") << " ";
      if ( source.second.is_remote() ) {
        std::cerr << "Download from " << source.second.cache().cache_uri();
      } else {
        std::cerr << "Already fetched";
      }
      std::cerr << std::endl;
    }

    if ( source.second.is_remote() ) {
      auto found(source.second.cache().store()->queryPathInfo(source.first));
      totalNarSize += found->narSize;
      pathCnt ++;
    }
  }

  // Download all the things!

  size_t complete(0);
  for ( auto path: pathOrder ) {
    auto &source(*sources.find(path));
    if ( source.second.is_remote() ) {
      auto info(source.second.cache().store()->queryPathInfo(source.first));

      auto dlSource = nix::sinkToSource
        ([&source, totalNarSize, &complete] ( nix::Sink &sink ) {
           nix::LambdaSink wrapper([&source, totalNarSize, &complete, &sink] ( const unsigned char *data, size_t len ) {
                                     sink(data, len);
                                     complete += len;
                                     std::cout << complete << " " << totalNarSize << " Downloading " << source.first << std::endl;
                                   });
           source.second.cache().store()->narFromPath(source.first, wrapper);
         });

      localStore->addToStore(*info, *dlSource, nix::NoRepair, nix::NoCheckSigs);
    }
  }

  std::cout << complete << " " << totalNarSize << " Complete";

  return 0;

  // nix::Strings dest_paths, paths;
  // nix::PathSet closure_paths;
  // nix::PublicKeys ourKeys;
  // auto trustedKeys(nix::getDefaultPublicKeys());
  // std::list<const char*> rawKeys;

  // nix::logger = nix::makeJSONLogger(*nix::logger);

  // if ( argc < 3 ) usage();

  // auto remoteStore = nix::openStore(argv[1]);
  // int i;
  // bool allowUnsigned(false);

  // for ( i = 2; i < argc; ++i ) {
  //   if ( std::string(argv[i]) == "--public-key" ) {
  //     if ( (i + 1) >= argc ) {
  //       std::cerr << "Missing argument after --public-key" << std::endl;
  //     } else {
  //       nix::PublicKey newKey(std::string(argv[++i]));
  //       std::cerr << "new key is " << newKey.name << std::endl;
  //       ourKeys.emplace(newKey.name, std::move(newKey));
  //       rawKeys.push_back(argv[i]);
  //     }
  //   } else if ( std::string(argv[i]) == "--allow-unsigned" ) {
  //     allowUnsigned = true;
  //   } else {
  //     std::cerr << "Add path " << argv[i] << std::endl;
  //     dest_paths.push_back(argv[i]);
  //   }
  // }

  // addPublicKeys(rawKeys);

  // auto localStore(nix::openStore());

  // for ( auto path: dest_paths ) {
  //   nix::DrvPathWithOutputs p = nix::parseDrvPathWithOutputs(path);
  //   paths.push_back(nix::makeDrvPathWithOutputs(localStore->followLinksToStorePath(p.first), p.second));
  // }

  // unsigned long long downloadSize;
  // nix::PathSet willDownload;
  // std::size_t dlSize(0);
  // bool hasUnknownSizes(false);

  // std::copy(paths.begin(), paths.end(), std::ostream_iterator<std::string>(std::cerr, "\n"));

  // remoteStore->computeFSClosure(nix::PathSet(paths.begin(), paths.end()), closure_paths);

  // // Now check each path in the local store. If it exists, it should
  // // either have been signed by the signing key for this remote store,
  // // or it should have been from a trusted signing key.

  // for ( const auto &path : closure_paths ) {
  //   std::cerr << "Checking for the existence of " << path << std::endl;

  //   try {
  //     auto path_info(localStore->queryPathInfo(path));

  //     // TODO: Ensure that this path is either from the main kite
  //     // store, or is from the same cache we're downloading from, or
  //     // is from a mutually trusted cache.

  //     if ( !path_info->ultimate &&
  //          !(allowUnsigned && path_info->sigs.size() == 0) ) {
  //       std::cerr << "Verifying path" << std::endl;
  //       if ( path_info->checkSignatures(*localStore, trustedKeys) == 0 ) {
  //         std::cerr << "This path was not generated by a trusted store" << std::endl;
  //         if ( path_info->checkSignatures(*localStore, ourKeys) == 0 ) {
  //           std::cerr << "Aborting because this path was not generated by our own store" << std::endl;
  //           return 11;
  //         }
  //       }
  //     }
  //   } catch (nix::InvalidPath &err) {
  //     willDownload.insert(path);

  //     auto path_info(remoteStore->queryPathInfo(path));

  //     if ( path_info->narSize == 0 ) {
  //       std::cerr << "Aborting fetch because it would be against Kite policy" << std::endl;
  //       return 10;
  //     } else
  //       dlSize += path_info->narSize;
  //   }
  // }

  // // narSize is total to be downloaded
  // std::cerr << "Will download " << std::endl;

  // auto willDownloadSorted(remoteStore->topoSortPaths(willDownload));
  // std::size_t dlProgress(0);

  // std::copy(willDownloadSorted.begin(), willDownloadSorted.end(),
  //           std::ostream_iterator<std::string>(std::cerr, "\n"));

  // nix::copyPaths(remoteStore, localStore, willDownload, nix::NoRepair, nix::CheckSigs, nix::Substitute);

  // return 0;
}
