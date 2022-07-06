

RSpec.describe CcipherBox::MemVault do

  it 'register given key and perform enc and dec on specific data' do
    
    key = SecureRandom.random_bytes(16)
    data = SecureRandom.random_bytes(64)

    subj = CcipherBox::MemVault.new("Genesis")
    subj.register("first", key)
    res = subj.encrypt("first",data)

    expect(res).not_to be nil

    plain = subj.decrypt(res)
    comp = Ccrypto::UtilFactory.instance(:comparator)
    expect(comp.is_equals?(plain,data)).to be true

  end

end
