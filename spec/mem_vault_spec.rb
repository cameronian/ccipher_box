

RSpec.describe CcipherBox::MemVault do

  it 'register given key and perform enc and dec on specific data' do
    
    key = SecureRandom.random_bytes(16)
    data = SecureRandom.random_bytes(64)

    subject.register("first", key)
    res = subject.encrypt("first",data)

    expect(res).not_to be nil

    plain = subject.decrypt(res)
    comp = Ccrypto::UtilFactory.instance(:comparator)
    expect(comp.is_equals?(plain,data)).to be true

  end

end
