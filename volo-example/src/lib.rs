pub struct S;

impl volo_gen::volo::example::ItemService for S {
    async fn get_item(
        &self,
        _req: volo_gen::volo::example::GetItemRequest,
    ) -> ::core::result::Result<volo_gen::volo::example::GetItemResponse, ::volo_thrift::ServerError>
    {
        ::std::result::Result::Ok(Default::default())
    }
}