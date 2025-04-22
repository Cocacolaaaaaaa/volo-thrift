use faststr::FastStr;
use volo_gen::volo::example::Item;
use ahash::AHashMap;

pub struct S;

impl volo_gen::volo::example::ItemService for S {
    async fn get_item(
        &self,
        req: volo_gen::volo::example::GetItemRequest,
    ) -> ::core::result::Result<volo_gen::volo::example::GetItemResponse, ::volo_thrift::ServerError>
    {
        let item = Item {
            id: req.id,
            title: format!("Item {}", req.id).into(), // 将 String 转换为 FastStr
            content: format!("This is the content for item {}", req.id).into(), // 将 String 转换为 FastStr
            extra: Some(AHashMap::new()), // 这里可以为空的 AHashMap
        };

        let response = volo_gen::volo::example::GetItemResponse {
            item,
        };

        Ok(response)
    }
}

// pub struct S;

// impl volo_gen::volo::example::ItemService for S {
//     async fn get_item(
//         &self,
//         _req: volo_gen::volo::example::GetItemRequest,
//     ) -> ::core::result::Result<volo_gen::volo::example::GetItemResponse, ::volo_thrift::ServerError>
//     {
//         ::std::result::Result::Ok(Default::default())
//     }
// }