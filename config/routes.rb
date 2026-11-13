get 'admin/stronger_security', to: 'stronger_security#index', as: 'stronger_security'
get 'admin/stronger_security/dependencies', to: 'stronger_security#dependencies', as: 'stronger_security_dependencies'
post 'admin/stronger_security/dependencies/collect', to: 'stronger_security#collect_dependencies', as: 'stronger_security_collect_dependencies'
