module Scandium
  class ACL
    # holds the value for a white list type of acl
    WHITE_LIST = :white_list
    
    # holds the value for a black list type of acl
    BLACK_LIST = :black_list
    
    # holds the type of value that an allow rule has
    TYPE_ALLOW = :allow
    
    # holds the type of value that a deny rule has
    TYPE_DENY  = :deny
    
    attr_accessor :roles, :resources, :rules
    
    # Initializes the acl instance and sets the configuration parameters
    # for the acl to work.
    # @argument acl_type = WHITE_LIST
    # @argument options = {} the rules, roles, resources and default assert block for the acl.
    def initialize(acl_type = WHITE_LIST, options = {})
      assert      = options[:assert]    || options['assert']
      @roles      = options[:roles]     || options['roles']     || {}
      @resources  = options[:resources] || options['resources'] || {}
      @rules      = options[:rules]     || options['rules']     || {
        :all_resources => {
          :all_roles => {
            :all_privileges => {
              :type => acl_type == WHITE_LIST ? TYPE_DENY : TYPE_ALLOW,
              :assert => assert ? assert.to_proc : nil
            }
          }
        }
      }
    end
    
    # adds a role to the acl system
    # @argument role [Scandium::Role]
    # @argument parents [Array] []
    def add_role(role, parents = [])
      raise "Role #{role} is not an instance of Scandium::Role instead is #{role.class}" unless role.is_a?(Scandium::Role) 
      id = role.id
      raise "Role #{role.id} is already defined" if roles[id]
      
      roles[id] = {
        :instance => role,
        :parents  => [],
        :children => [] 
      }

      (parents.class == Array ? parents : [parents]).each do |parent_role|
        raise "Role #{parent_role} does not exists" unless roles[parent_role]
        
        roles[id][:parents].unshift roles[parent_role][:instance]
        roles[parent_role][:children] << roles[id][:instance]
      end
    end
    
    # Adds a resource to the acl system
    # @argument resource [Scandium::Resource]
    def add_resource(resource)
      resources[resource.id] = resource
    end
    
    # Defines an authorized rule for the acl system
    # @argument action [Symbol] it can be any symbol, but a special symbol, :allPrivileges
    # means that any privilege is authorized, this way avoid the need to define privilege by privilege
    # @argument resource [Symbol]
    # @argument role [Symbol]
    # @argument assert [String], this will be evaluated in the context a proc to aid the authorization rule
    # with special conditions that may happen, this is a String instead of a Block due to the lack of serialization
    # options lacking on the Proc Object
    def allow(action, resource, role, assert = nil)
      set_rule action, resource, role, assert, TYPE_ALLOW
    end
    
    # Sets a deny rule to the acl system, all arguments are the same as allow method but for denial
    def deny(action, resource, role, assert = nil)
      set_rule action, resource, role, assert, TYPE_DENY
    end
    
    def allows?(action, resource, role, *assertArguments)
      rule   = get_rule(action, resource, role) || rules[:all_resources][:all_roles][:all_privileges]
      assert = rule[:assert] ? rule[:assert].call(*assertArguments) : true
      assert && rule[:type] == TYPE_ALLOW
    end
    
    def denies?(action, resource, role, *assertArguments)
      !allows? action, resource, role, *assertArguments
    end
    
    def get_rule(action, resource, role)
      action, resource, role = action.to_sym, resource.to_sym, role.to_sym
      
      rule = get_raw_rule(action, resource, role)  ||
        get_raw_rule(action, resource, :all_roles) ||
        get_raw_rule(action, :all_resources, role) ||
        rules[:all_resources][role][:all_privileges] rescue nil
      
      roles[role][:parents].each do |parent_role|
        rule = get_rule(action, resource, parent_role.id)
        break if rule
      end if !rule && roles[role]
      
      rule
    end
    
    def get_raw_rule(action, resource, role)
      rules[resource][role][action] || rules[resource][role][:all_privileges]
    rescue 
      nil
    end
    
    def set_rule(action, resource, role, assert, type)
      action, resource, role = action.to_sym, resource.to_sym, role.to_sym
      rules[resource]               = {} unless rules[resource]
      rules[resource][role]         = {} unless rules[resource][role]
      rules[resource][role][action] = {
        :type   => type,
        :assert => assert ? assert.to_proc : assert
      }
    end
    
    private :get_rule, :get_raw_rule, :set_rule
  end
  
  class Role
    attr_reader :id
    def initialize(id)
      @id = id.to_sym
    end
  end
  
  class Resource
    attr_reader :id
    def initialize(id)
      @id = id.to_sym
    end
  end
end

Sc = Scandium
