require File.expand_path(File.dirname(__FILE__) + '/spec_helper')

context "Scandium" do
  describe "Module" do
    it "should be the same to call Scandium or Sc" do
      Scandium.should == Sc
    end
  end
  
  describe 'API' do
    it "should be the same to call Sc or Scandium" do
      Sc.should equal Scandium
    end
    
    it "should have ACL class" do
      Scandium::ACL.class.should == Class
    end

    it "should have Role class" do
      Scandium::Role.class.should == Class
    end

    it "should have Resource class" do
      Scandium::Resource.class.should == Class
    end
  end
  
  describe ":: Role" do
    it "should expose id from the initialization process" do
      Scandium::Role.new(:user).id.should == :user
    end
  end
  
  describe ":: Resource" do
    it "should expose id from the initialization process" do
      Scandium::Resource.new(:record).id.should == :record
    end
  end
  
  describe ':: ACL instance methods' do
    context 'initialize' do
      it 'should be a white list based acl by default' do
        acl = Scandium::ACL.new
        acl.rules[:all_resources][:all_roles][:all_privileges][:type].should == Scandium::ACL::TYPE_DENY
      end

      it "should be a black list if specified as so" do
        acl = Scandium::ACL.new Scandium::ACL::BLACK_LIST
        acl.rules[:all_resources][:all_roles][:all_privileges][:type].should == Scandium::ACL::TYPE_ALLOW
      end

      it "should have an empty hash on resources when no resources passed on options" do
        resources = {}
        acl = Scandium::ACL.new
        acl.resources.should == resources
      end

      it "should have resources assigned when passed on param options" do
        resources = {
          :users => Scandium::Resource.new(:users),
          :posts => Scandium::Resource.new(:posts)
        }
        acl = Scandium::ACL.new nil, {
          :resources => resources
        }
        acl.resources.should eql resources
      end

      it "should have an empty hash on roles when no roles passed on options" do
        roles = {}
        acl   = Scandium::ACL.new
        acl.roles.should == roles
      end

      it "should have roles assigned when passed on param options" do
        roles = {
          :root          => Scandium::Role.new(:root),
          :administrator => Scandium::Role.new(:administrator)
        }
        acl = Scandium::ACL.new nil, {
          :roles => roles
        }
        acl.roles.should eql roles
      end

      it "should have the default data structure for rules, when no rules are passed on options" do
        rules = {
          :all_resources => {
            :all_roles => {
              :all_privileges => {
                :type => Scandium::ACL::TYPE_DENY,
                :assert => nil
              }
            }
          }
        }
        Scandium::ACL.new.rules.should == rules
      end

      it "should have the passed data structure for rules, when rules are passed on options" do
        rules = {
          :all_resources => {
            :all_roles => {
              :all_privileges => {
                :type => Scandium::ACL::TYPE_ALLOW,
                :assert => nil
              }
            }
          }
        }
        acl = Scandium::ACL.new(nil, {:rules => rules})
        acl.rules.should == rules
      end
    end
    
    describe "add_role" do
      it "should add a role" do
        acl = Scandium::ACL.new
        role = Scandium::Role.new :user
        acl.add_role role
        acl.roles[:user][:instance].should equal role
      end
      
      it "should raise an exeption when adding a role with an id that already exists in the acl" do
        acl = Scandium::ACL.new
        role = Scandium::Role.new :user
        role2 = Scandium::Role.new :user
        acl.add_role role
        lambda { acl.add_role(role2) }.should raise_error "Role #{role2.id} is already defined"
      end
      
      it "should raise an exeption when adding a role not instance of Scandium::Role" do
        acl = Scandium::ACL.new
        role = Scandium::Resource.new :user
        lambda { acl.add_role(role) }.should raise_error "Role #{role} is not an instance of Scandium::Role instead is #{role.class}"
      end
    end
    
    describe "add_resource" do
      it "should add a resource" do
        acl = Scandium::ACL.new
        resource = Scandium::Resource.new :record
        acl.add_resource resource
        acl.resources[:record].should equal resource
      end
    end
    
    describe "allow" do
      it "should set a rule as TYPE_ALLOW with the sent paramenters" do
        acl = Scandium::ACL.new
        acl.allow :write, :record, :user
        acl.rules[:record][:user][:write][:type].should == Scandium::ACL::TYPE_ALLOW
      end
    end
    
    describe "deny" do
      it "should set a rule as TYPE_DENY with the sent paramenters" do
        acl = Scandium::ACL.new
        acl.deny :write, :record, :user
        acl.rules[:record][:user][:write][:type].should == Scandium::ACL::TYPE_DENY
      end
    end
    
    describe "allows?" do
      it "should return true when the rule is defined" do
        acl = Scandium::ACL.new
        acl.allow :write, :record, :user
        acl.allows?(:write, :record, :user).should == true
      end
    end
    
    describe "denies?" do
      it "should return false when the rule is defined" do
        acl = Scandium::ACL.new
        acl.deny :write, :record, :user
        acl.denies?(:write, :record, :user).should == true
      end
    end
  end
  
  describe 'Basic Usage' do
    before :each do
      @acl = Scandium::ACL.new
      @acl.add_role Scandium::Role.new(:user)
      @acl.add_resource Scandium::Resource.new(:record)
    end
    
    it "should deny all by default" do
      @acl.allows?(:write, :record, :user).should == false
      @acl.allows?(:read, :document, :user).should == false
    end
    
    it "should allow if the rule for privilege, resource for the role is specified as allowed" do
      @acl.allow :write, :record, :user
      @acl.allows?(:write, :record, :user).should == true
    end
    
    it "should allow if the rule for :all_privileges, resource for the role is specified as allowed" do
      @acl.allow :all_privileges, :record, :user
      @acl.allows?(:read, :record, :user).should == true
      @acl.allows?(:write, :record, :user).should == true
    end
    
    it "should allow if the rule is allowed to all privileges for the resource" do
      @acl.allow :all_privileges, :record, :all_roles
      @acl.allows?(:read, :record, :user).should == true
    end
    
    it "should allow if the rule for :all_privileges, :all_resources for the role is specified as allowed" do
      @acl.add_resource Scandium::Resource.new(:other_record)
      
      @acl.allow :all_privileges, :all_resources, :user
      @acl.allows?(:read, :record, :user).should == true
      @acl.allows?(:write, :other_record, :user).should == true
    end
  end
  
  describe "Role inheritance" do
    before :each do
      @acl = Sc::ACL.new
      @acl.add_resource(Sc::Resource.new(:record))
      @acl.add_role(Sc::Role.new(:root))
      @acl.add_role(Sc::Role.new(:user), :root)
    end
    
    it "should allow role a privilege on a resource if parent is allowed that privilege on the resource" do
      @acl.allow(:all_privileges, :record, :root)
      @acl.allows?(:read, :record, :root).should == true
      @acl.allows?(:read, :record, :user).should == true
    end
    
    it "should deny role a privilege on a resource if denied for that role even if the parent is allowed" do
      @acl.allow(:all_privileges, :record, :root)
      @acl.deny(:all_privileges, :record, :user)
      @acl.allows?(:read, :record, :root).should == true
      @acl.allows?(:read, :record, :user).should == false
    end
    
    it "should allow role a privilege on a resource if one ancestor is allowed that privilege on the resource" do
      @acl.add_role(Sc::Role.new(:editor), :user)
      @acl.allow(:all_privileges, :record, :root)
      @acl.allows?(:read, :record, :root).should == true
      @acl.allows?(:read, :record, :editor).should == true
    end
    
    it "should allow role a privilege on a resource if last parent is allowed that privilege on the resource" do
      @acl.add_role(Sc::Role.new(:editor), [:root, :user])
      @acl.deny(:all_privileges, :record, :root)
      @acl.allow(:all_privileges, :record, :user)
      @acl.allows?(:read, :record, :root).should   == false
      @acl.allows?(:read, :record, :user).should   == true
      @acl.allows?(:read, :record, :editor).should == true
    end
    
    it "should deny role a privilege on a resource if last parent is denied that privilege on the resource" do
      @acl.add_role(Sc::Role.new(:editor), [:user, :root])
      @acl.deny(:all_privileges, :record, :root)
      @acl.allow(:all_privileges, :record, :user)
      @acl.allows?(:read, :record, :root).should   == false
      @acl.allows?(:read, :record, :user).should   == true
      @acl.allows?(:read, :record, :editor).should == false
    end
  end
  
  describe "conditional permission checking" do
    it "should describe conditional permission checking"
  end
end
