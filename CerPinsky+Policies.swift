//
//  CerPinsky+Policies.swift
//

import Alamofire

extension CerPinsky {
    
    enum Domains {
        static let google = "google.com"
    }
    
    static var benuPolicies: [String: ServerTrustPolicy] {
        let trustConfig: ServerTrustPolicy = .pinCertificates(certificates: ServerTrustPolicy.certificates(),
                                                              validateCertificateChain: true,
                                                              validateHost: true)
        let domains = [
            Domains.google
        ]
        
        var dictionary: [String: ServerTrustPolicy] = [:]
        
        domains.forEach {
            dictionary[$0] = trustConfig
            dictionary["www.\($0)"] = trustConfig
        }
        
        return dictionary
    }
}
